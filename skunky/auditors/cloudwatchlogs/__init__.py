from skunky.skunky import Auditor
from skunky.skunky import LOGGER


class CloudwatchLogsAuditor(Auditor):
    def audit(self, instance):
    	LOGGER.info("Instance {} in Account {} with IP {} in {} marked dirty - {}".format(
            instance['instance_id'], instance['instance_account_id'], instance['bastion_user_ip'],
            instance['instance_region'], instance.get('skunk_level', '?')))
