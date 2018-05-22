# -*- coding: utf-8 -*-
"""
Fortigate firewall log parser

Checks all incoming lines that starts with 'date='.
Output fields:
            time.source
            classification.type
            classification.identifier
            source.ip
            source.port
            destination.ip
            destination.port
            source.local_hostname
            status
            event_description.text
            event_description.url
"""
from datetime import datetime
import re

from intelmq.lib.bot import Bot
from intelmq.lib.utils import base64_decode

class FortiParserBot(Bot):

    def parse(self, regexp, line):
        matched = re.search(regexp, line)
        return matched.group(1) if matched else None

    def setTimestamp(self, sdate, stime):
        if stime:
            return sdate+"T"+stime+"+00:00"
        else:
            return sdate+"T00:00:00+00:00"

    def process(self):
        re_map={'date': 'date=(\S+)',
               'time': 'time=(\S+)',
               'attack': 'attack=\"(.*?)\"',
               'srcip': 'srcip=(\S+)',
               'srcport': 'srcport=(\S+)',
               'dstip': 'dstip=(\S+)',
               'dstport': 'dstport=(\S+)',
               'devname': 'devname=(\S+)',
               'logid': 'logid=(\S+)',
               'action': 'action=(\S+)',
               'ref': 'ref=\"(.*?)\"',
               'msg': 'msg=\"(.*?)\"'
        }

        report=self.receive_message()
        line=base64_decode(report['raw'])
        event_found=re.search('^date=', line)
        if event_found:
            event = self.new_event(report)
            event.add('time.source', self.setTimestamp(self.parse(re_map['date'], line), self.parse(re_map['time'], line)))
            event.add('classification.type', 'ids alert')
            event.add('classification.identifier', self.parse(re_map['attack'], line))
            event.add('source.ip', self.parse(re_map['srcip'], line))
            event.add('source.port', self.parse(re_map['srcport'], line))
            event.add('destination.ip', self.parse(re_map['dstip'], line))
            event.add('destination.port', self.parse(re_map['dstport'], line))
            event.add('source.local_hostname', self.parse(re_map['devname'], line))
            event.add('status', self.parse(re_map['action'], line))
            event.add('event_description.text', self.parse(re_map['msg'], line))
            event.add('event_description.url', self.parse(re_map['ref'], line))
            self.send_message(event)
        self.acknowledge_message()

BOT = FortiParserBot
