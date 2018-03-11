from skunky.skunky import Filter
from skunky.skunky import LOGGER


class EventFilter(Filter):
    def apply(self, input):
        if input.get('event', '') == 'ssh':
            input['skunk_level'] = self.config.get('ssh', 'high')
        else:
            input['skunk_level'] = self.config.get('unknown', 'critical')

        return False
