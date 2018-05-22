# -*- coding: utf-8 -*-
"""
DDoS action log parser

Output fields:
            time.source
            classification.type: ddos
            classification.taxonomy: DDoS attack
            source.ip
            status
            event_description.text
            extra.ddos_volume
"""
from datetime import datetime
import re

from intelmq.lib.bot import Bot
from intelmq.lib.utils import base64_decode

class DDoSParserBot(Bot):

    def parse(self, regexp, line):
        matched = re.search(regexp, line)
        return matched.group('match') if matched else None

    def setTimestamp(self, sdate, stime):
        if stime:
            return sdate+"T"+stime+"+00:00"
        else:
            return sdate+"T00:00:00+00:00"

    def process(self):
        re_map={'date': ' at (?P<match>\d{4}\-\d{2}\-\d{2})',
               'time': ' at \d{4}\-\d{2}\-\d{2} (?P<match>\S+)',
               'srcip': 'Address (?P<match>\S+)',
               'action': 'Address \S+(\s\(Default?\))? (?P<match>.*?) at',
               'msg': 'Comment \- (?P<match>.*)',
               'ddos_volume': 'Comment \- .*\: (Default \- )?(?P<match>.*bps)'
        }
        report=self.receive_message()
        line=base64_decode(report['raw'])
        event_found=re.search('Address \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', line)
        if event_found:
            event = self.new_event(report)
            event.add('time.source', self.setTimestamp(self.parse(re_map['date'], line), self.parse(re_map['time'], line)))
            event.add('classification.type', 'ddos')
            event.add('classification.taxonomy', 'DDoS attack')
            event.add('source.ip', self.parse(re_map['srcip'], line))
            event.add('status', self.parse(re_map['action'], line))
            event.add('event_description.text', self.parse(re_map['msg'], line))
            event.add('extra.ddos_volume', self.parse(re_map['ddos_volume'], line))
            self.send_message(event)
        self.acknowledge_message()

BOT = DDoSParserBot
