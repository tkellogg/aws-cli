from awscli.testutils import BaseAWSCommandParamsTest

class TestGenerateCerts(BaseAWSCommandParamsTest):
	prefix = 'iot generate-certs '

	def test_cmd_args(self):
		cmdline = self.prefix + '--policy-name Pub2DaSub --base-dir /tmp/foosball'
		self.assert_params_for_cmd(cmdline)
