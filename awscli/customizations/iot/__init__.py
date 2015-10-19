import os, platform, stat
from awscli.customizations.commands import BasicCommand

ROOTCA = """\
-----BEGIN CERTIFICATE-----
MIIE0zCCA7ugAwIBAgIQGNrRniZ96LtKIVjNzGs7SjANBgkqhkiG9w0BAQUFADCB
yjELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQL
ExZWZXJpU2lnbiBUcnVzdCBOZXR3b3JrMTowOAYDVQQLEzEoYykgMjAwNiBWZXJp
U2lnbiwgSW5jLiAtIEZvciBhdXRob3JpemVkIHVzZSBvbmx5MUUwQwYDVQQDEzxW
ZXJpU2lnbiBDbGFzcyAzIFB1YmxpYyBQcmltYXJ5IENlcnRpZmljYXRpb24gQXV0
aG9yaXR5IC0gRzUwHhcNMDYxMTA4MDAwMDAwWhcNMzYwNzE2MjM1OTU5WjCByjEL
MAkGA1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQLExZW
ZXJpU2lnbiBUcnVzdCBOZXR3b3JrMTowOAYDVQQLEzEoYykgMjAwNiBWZXJpU2ln
biwgSW5jLiAtIEZvciBhdXRob3JpemVkIHVzZSBvbmx5MUUwQwYDVQQDEzxWZXJp
U2lnbiBDbGFzcyAzIFB1YmxpYyBQcmltYXJ5IENlcnRpZmljYXRpb24gQXV0aG9y
aXR5IC0gRzUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCvJAgIKXo1
nmAMqudLO07cfLw8RRy7K+D+KQL5VwijZIUVJ/XxrcgxiV0i6CqqpkKzj/i5Vbex
t0uz/o9+B1fs70PbZmIVYc9gDaTY3vjgw2IIPVQT60nKWVSFJuUrjxuf6/WhkcIz
SdhDY2pSS9KP6HBRTdGJaXvHcPaz3BJ023tdS1bTlr8Vd6Gw9KIl8q8ckmcY5fQG
BO+QueQA5N06tRn/Arr0PO7gi+s3i+z016zy9vA9r911kTMZHRxAy3QkGSGT2RT+
rCpSx4/VBEnkjWNHiDxpg8v+R70rfk/Fla4OndTRQ8Bnc+MUCH7lP59zuDMKz10/
NIeWiu5T6CUVAgMBAAGjgbIwga8wDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8E
BAMCAQYwbQYIKwYBBQUHAQwEYTBfoV2gWzBZMFcwVRYJaW1hZ2UvZ2lmMCEwHzAH
BgUrDgMCGgQUj+XTGoasjY5rw8+AatRIGCx7GS4wJRYjaHR0cDovL2xvZ28udmVy
aXNpZ24uY29tL3ZzbG9nby5naWYwHQYDVR0OBBYEFH/TZafC3ey78DAJ80M5+gKv
MzEzMA0GCSqGSIb3DQEBBQUAA4IBAQCTJEowX2LP2BqYLz3q3JktvXf2pXkiOOzE
p6B4Eq1iDkVwZMXnl2YtmAl+X6/WzChl8gGqCBpH3vn5fJJaCGkgDdk+bW48DW7Y
5gaRQBi5+MHt39tBquCWIMnNZBU4gcmU7qKEKQsTb47bDN0lAtukixlE0kF6BWlK
WE9gyn6CagsCqiUXObXbf+eEZSqVir2G3l6BFoMtEMze/aiCKm0oHw0LxOXnGiYZ
4fQRbxC1lfznQgUy286dUV4otp6F01vvpX1FQHKOtw5rDgb7MzVIcbidJ4vEZV8N
hnacRHr2lVz2XTIIM6RUthg/aFzyQkqFOFSDX9HoLPKsEdao7WNq
-----END CERTIFICATE-----
"""

DEFAULT_POLICY = """\
{
    "Version": "2012-10-17", 
    "Statement": [{
        "Effect": "Allow",
        "Action":["iot:*"],
        "Resource": ["*"]
    }]
}
"""

def register_customizations(cli):
	cli.register('building-command-table.iot', register_commands)


def register_commands(command_table, session, **kwargs):
	command_table['scaffold-certs'] = GenerateCertsCommand(session)

class GenerateCertsCommand(BasicCommand):
	NAME = 'scaffold-certs'
	DESCRIPTION = (
		'Generate certificates and encryption keys as well as two scripts '
		'that act as thin wrappers around mosquitto_pub and mosquitto_sub '
		'to quickly get started with MQTT. This command generates several '
		'files on your computer, so specify --base-dir to make them go '
		'somewhere other than right here.')
	ARG_TABLE = [
		{'name': 'base-dir', 'help_text': (
				'The directory on your computer where to generate all these files. '
				'The default is current working directory'),
			'action': 'store', 'required': False, 'cli_type_name': 'string', },
		{'name': 'policy-name',
			'help_text': (
				'The name of the policy that enables the new device to publish and '
				'subscribe over MQTT. Default value is "PubSubToAnyTopic"'),
			'action': 'store', 'required': False},
	]

	def __init__(self, session):
		super(GenerateCertsCommand, self).__init__(session)

	def _run_main(self, parsed_args, parsed_globals, **kwargs):
		# We need region for writing publish.sh & subscribe.sh files later
		if parsed_globals.region:
			self._region = parsed_globals.region
		else:
			profile = parsed_globals.profile or 'default'
			if profile in self._session.full_config['profiles']:
				profile_config = self._session.full_config['profiles'][profile]
				if 'region' in profile_config:
					self._region = profile_config['region']
			else:
				raise ArgumentError("Specified profile '{0}' not found".format(profile))

		if not self._region:
			self._region = 'us-east-1'

		self._set_client(parsed_globals)
		self._process_args(parsed_args)
		self._generate_certs(parsed_args)

		self._print_instructions()

		# This is to make the functional test pass. Maybe we can write a better test?
		return 0

	def _set_client(self, parsed_globals):

		# This is called from _run_main and is used to ensure that we have
		# a service/endpoint object to work with.
		self.client = self._session.create_client('iot', 
			region_name = self._region,
			endpoint_url = parsed_globals.endpoint_url,
			verify = parsed_globals.verify_ssl)

	def _process_args(self, parsed_args):
		self._base_dir = os.path.abspath(parsed_args.base_dir or '.')
		self._policy_name = parsed_args.policy_name or 'PubSubToAnyTopic'
		self._policy_document = DEFAULT_POLICY

	def _generate_certs(self, parsed_args):

		# Ensure that the destination exists
		if not os.path.exists(self._base_dir):
			os.makedirs(self._base_dir)

		certs = self.client.create_keys_and_certificate(setAsActive = True)
		
		self._write_file('certificate.pem', certs['certificatePem'])
		self._write_file('certificate-arn.txt', certs['certificateArn'])
		self._write_file('certificate-id.txt', certs['certificateId'])
		self._write_file('public.pem', certs['keyPair']['PublicKey'])
		self._write_file('private.pem', certs['keyPair']['PrivateKey'])

		self.client.create_policy(policyName = self._policy_name,
			policyDocument = self._policy_document)

		self.client.attach_principal_policy(principal = certs['certificateArn'],
			policyName = self._policy_name)

		self._write_file('rootCA.pem', ROOTCA)
		self._write_publish()
		self._write_subscribe()

	def _write_file(self, fname, value):
		path = os.path.join(self._base_dir, fname)
		handle = open(path, 'w')
		handle.write(value)
		handle.close()
		
	def _write_publish(self):
		self._write_script_file('publish', 'mosquitto_pub')

	def _write_subscribe(self):
		self._write_script_file('subscribe', 'mosquitto_sub')

	def _write_script_file(self, name, cmd):
		if platform.uname()[0] == 'Windows':
			ext = '.bat'
			all_args = "%*"
			prelude = ""
		else:
			ext = '.sh'
			all_args = '"$@"'
			prelude = "#!/bin/sh\n\n"

		# We use this in _print_instructions
		self._ext = ext

		params = (
			" --cafile \"{0}{2}rootCA.pem\" "
			"--cert \"{0}{2}cert.pem\" "
			"--key \"{0}{2}private.pem\" "
			"-h data.iot.{1}.amazonaws.com "
			"-p 8883 ").format(self._base_dir, self._region, os.sep)

		fname = name + ext
		content = prelude + cmd + params + all_args

		self._write_file(fname, content)

		st = os.stat(fname)
		os.chmod(fname, st.st_mode | stat.S_IEXEC)

	def _print_instructions(self):
		msg = (
			'Welcome! You are now ready to publish and subscribe to MQTT topics. '
			'We have written several files to "{0}":\n'
			'\n'
			' * certificate.pem - the X.509 certificate that represents the '
			'virtual device that was just registered.\n'
			' * certificate-arn.txt - contains just the ARN of the certificate, '
			'so you don\'t forget.\n'
			' * certificate-id.txt - contains just the ID of the certificate, '
			'so you don\'t forget.\n'
			' * public.pem - the public key.\n'
			' * private.pem - the private key.\n'
			' * publish{1} - a script to help you publish to MQTT topics.\n'
			' * subscribe{1} - a script to help you subscribe to MQTT topics.\n'
			'\n'
			'The publish{1} and subscribe{1} scripts are just thin wrappers '
			'around mosquitto_pub and mosquitto_sub, respectively. Mosquitto is '
			'a popular MQTT command-line client. You can absolutely use these '
			'scripts as a guide to use any other MQTT client that you want.\n'
			'\n'
			'Now you\'re ready to get started. Try running this command:\n'
			'\n'
			'    publish{1} -t some/topic -m "AWS IoT is fun" -d\n'
			'\n'
			'At any point, use the --help option on publish{1} or subscribe{1} '
			'to get a full listing of options that mosquitto_pub and/or mosquitto_sub '
			'supports.')

		msg = msg.format(self._base_dir, self._ext)
		for line in msg.splitlines():
			print line

	
