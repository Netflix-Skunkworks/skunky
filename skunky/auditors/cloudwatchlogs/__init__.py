from skunky.skunky import Auditor
from skunky.skunky import LOGGER


class CloudwatchLogsAuditor(Auditor):
    def audit(self, instance):
    	LOGGER.info("Instance {} in Account {} with IP {} in {} marked dirty - {}".format(
            instance['instanceId'], instance['accountId'], instance['privateIp'],
            instance['region'], instance.get('skunk_level', '?')))
