# -*- coding: utf-8 -*-
"""
clean-mx.com PhishWatch report parser

Output fields:
        "classification.type" : 'phishing'
        "classification.taxonomy": 'fraud'
        "source.ip"
        "source.url"
"""
import re

from intelmq.lib.bot import Bot
from intelmq.lib.utils import base64_decode

class CleanMXPhishWatchParserBot(Bot):

    def process(self):
        event_category_list=['Security Services']
        report = self.receive_message()
        line = base64_decode(report['raw'])

        event_found = re.search('(?P<status>^Up\S+|^Down)\:\t(?P<ip1>\S+)?\t( to\s(?P<ip2>\S+)?)?\t(?P<domain>\S+)?\t(?P<url>\S+)?', line)
        if event_found:
            event = self.new_event(report)
            event.add('classification.type', 'phishing')
            event.add('classification.taxonomy', 'fraud')
            if event_found.group('ip1'): event.add('source.ip', event_found.group('ip1'))
            if  event_found.group('url'): event.add('source.url', event_found.group('url'))
            self.send_message(event)
        self.acknowledge_message()

BOT = CleanMXPhishWatchParserBot
