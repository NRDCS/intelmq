# -*- coding: utf-8 -*-
"""
SonicWall firewall log parsers

Checks all incoming lines and only parses events under Categories
listed in 'event_category_list' list.
Output fields:
        "time.source"
        "classification.type" : 'ids alert'
        "classification.taxonomy"
        "source.ip"
        "source.port"
        "destination.ip"
        "destination.port"
        "protocol.transport"
        "event_description.text", 'IP spoof dropped'
        "raw" : raw event
"""
from datetime import datetime
import re

from intelmq.lib.bot import Bot
from intelmq.lib.utils import base64_decode

class SonicWallParserBot(Bot):

    def process(self):
        event_category_list=['Security Services']
        report = self.receive_message()
        line = base64_decode(report['raw'])

        event_found = re.search('(\d{2}\/\d{2}\/\d{4}\s+\d{2}\:\d{2}\:\d{2})\s+\-\s+\S+\s+\-\s+([a-zA-Z0-9\s]+)\s+\-\s+([a-zA-Z0-9\s]+)\s+\-\s+(.*)', line)
        if event_found:
            if event_found.group(2) in event_category_list:
                    event_details = re.search('^(\S+), (\d+), \S+ \- (\S+), (\d+), \S+ \- (\S+) \- (.*)', event_found.group(4))
                    event = self.new_event(report)
                    event.add('time.source', datetime.strftime(datetime.strptime(event_found.group(1), '%m/%d/%Y %H:%M:%S'), '%Y-%m-%dT%H:%M:%S+00:00'))
                    event.add('classification.type', 'ids alert')
                    event.add('classification.taxonomy', event_details.group(6))
                    event.add('source.ip', event_details.group(1))
                    event.add('source.port', event_details.group(2))
                    event.add('destination.ip', event_details.group(3))
                    event.add('destination.port', event_details.group(4))
                    event.add('protocol.transport',event_details.group(5))
                    event.add('event_description.text', 'IP spoof dropped')
                    event.add('raw', line)
                    self.send_message(event)
        self.acknowledge_message()

BOT = SonicWallParserBot

