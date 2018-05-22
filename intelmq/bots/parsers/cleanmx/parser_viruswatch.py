# -*- coding: utf-8 -*-
"""
clean-mx.com VirusWatch report parser

Output fields:
        "classification.type" : 'malware'
        "classification.taxonomy": 'malicious code'
		"source.geolocation.cc"
		"source.account"
        "source.ip"
        "source.url"
"""
import re

from intelmq.lib.bot import Bot
from intelmq.lib.utils import base64_decode

class CleanMXVirusWatchParserBot(Bot):

    def process(self):
        event_category_list=['Security Services']
        report = self.receive_message()
        line = base64_decode(report['raw'])

        event_found=re.search('(?P<status>^Up\S+|^Down)\:\t(?P<html1>\S+)?\t(?P<provider>\S+)?\t(?P<country>\S+)?' \
                              '\t(?P<email>\S+)?\t(?P<ip1>\S+)?\t( to\s(?P<ip2>\S+)?)?\t(?P<domain>\S+)?\t(?P<url>\S+)', line)
        if event_found:
            event = self.new_event(report)
            event.add('classification.type', 'malware')
            event.add('classification.taxonomy', 'malicious code')
            if  event_found.group('country'): event.add('source.geolocation.cc', event_found.group('country'))
            if  event_found.group('email'): event.add('source.account', event_found.group('email'))
            if  event_found.group('ip1'): event.add('source.ip', event_found.group('ip1'))
            if  event_found.group('url'): event.add('source.url', event_found.group('url'))
            self.send_message(event)
        self.acknowledge_message()

BOT = CleanMXVirusWatchParserBot
