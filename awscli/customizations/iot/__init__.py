# Copyright 2015 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You
# may not use this file except in compliance with the License. A copy of
# the License is located at
#
#     http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
# ANY KIND, either express or implied. See the License for the specific
# language governing permissions and limitations under the License.

"""
This module adds the `aws iot scaffold-certs` subcommand that glues a
few API calls together to quickly get a working command line MQTT client
for an AWS account & region.
"""

import os, platform, stat
from awscli.customizations.commands import BasicCommand

# The VeriSign rootCA.pem file can't be packaged here due to distribution 
# restrictions. Therefore, we download it on the user's behalf.
ROOTCA = "$(curl http://www.symantec.com/content/en/us/enterprise/verisign/roots/VeriSign-Class%203-Public-Primary-Certification-Authority-G5.pem)"

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
			'around mosquitto_pub and mosquitto_sub, respectively. Eclipse '
			'Mosquitto (http://www.eclipse.org/mosquitto/) is a popular MQTT '
			'command-line client. You can absolutely use these scripts as a '
			'guide to use any other MQTT client that you want.\n'
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

	
