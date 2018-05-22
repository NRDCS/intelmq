# -*- coding: utf-8 -*-
"""
blocklist.de report parser

Output fields:
            time.source
            classification.type: brute-force
            classification.taxonomy: intrusion attempts
            source.ip
            destination.port
            event_description.url
"""
from datetime import datetime
import re

from intelmq.lib.bot import Bot
from intelmq.lib.utils import base64_decode

class BlocklistReportParserBot(Bot):

    def parse(self, regexp, line):
        matched = re.search(regexp, line)
        return matched.group('match') if matched else None

    def setTimestamp(self, sdate, stime):
        if stime:
            return sdate+"T"+stime+"+00:00"
        else:
            return sdate+"T00:00:00+00:00"

    def process(self):
        f=open('/home/am/bot_output.txt','a')

        re_map={'date': 'Date: (?P<match>.*)',
                'type': 'Report-Type: (?P<match>.*)',
                'srcip': 'Source: (?P<match>\S+)',
                'dstport': 'Port: (?P<match>\S+)',
                'url': 'Schema-URL: (?P<match>\S+)',
                'attach': 'Attachment: (?P<match>.*)',
                'from': 'Reported-From: (?P<match>\S+)'
        }
        report=self.receive_message()
        raw_data=base64_decode(report['raw'])
        splited=raw_data.splitlines()
        event = self.new_event(report)
        event.add('classification.taxonomy', 'intrusion attempts')
        event.add('classification.type', 'brute-force')
        for line in splited:
            if self.parse(re_map['date'], line): event.add('time.source',
                                                           datetime.strftime(datetime.strptime(self.parse(re_map['date'], line),
                                                           '%a, %d %b %Y %H:%M:%S %z'), '%Y-%m-%dT%H:%M:%S%z')
                                                          )
            if self.parse(re_map['srcip'], line): event.add('source.ip', self.parse(re_map['srcip'], line))
            if self.parse(re_map['dstport'], line): event.add('destination.port', self.parse(re_map['dstport'], line))
            if self.parse(re_map['url'], line): event.add('event_description.url', self.parse(re_map['url'], line))
        self.send_message(event)
        self.acknowledge_message()

BOT = BlocklistReportParserBot
