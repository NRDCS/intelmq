# -*- coding: utf-8 -*-

"""
T-POT honeypot report collector bot
Queries ElasticSearch to get events from T-POT honeypots.

Parameters:
    elk_url: string
    query_file: string
    period_to_query: int
    honeypot_count: int
    connection_value_sum: int
    classification: string
"""

import requests, json
from intelmq.lib.bot import CollectorBot


class HoneypotCollectorBot(CollectorBot):

    def process(self):
        elk_url = self.parameters.elk_url
        query_file = self.parameters.query_file
        period_to_query = self.parameters.period_to_query
        honeypot_count = self.parameters.honeypot_count
        connection_value_sum = self.parameters.connection_value_sum
        classification = self.parameters.classification

        headers = {'Content-Type': 'application/json'}

        # Adding period_to_query value as a timestamp value into ELK query
        elk_query = json.load(open(query_file))
        for item in elk_query['query']['bool']['must']:
            if 'range' in item:
                for key, value in item.items():
                    for k, v in value.items():
                        v['gte'] = 'now-' + str(period_to_query) + 'h'

        self.logger.info('Honeypot to IntelMQ processing started')
        response = requests.get(elk_url, data=json.dumps(elk_query), headers=headers, verify=False)
        if response.status_code == 200 and 'took' in response.text:
            honeypot_report = json.loads(response.text)
            aggs = next(iter(honeypot_report['aggregations']))
            for item in honeypot_report['aggregations'][aggs]['buckets']:
                for key, value in item.items():
                    if type(value) == dict:
                        # Checking if bucket values matches search criteria
                        if len(value.get('buckets')) >= honeypot_count and item.get('doc_count') >= connection_value_sum:
                            line = {}
                            line.update({'source.ip': item.get('key')})
                            line.update({'classification.type': classification})
                            report = self.new_report()
                            report.add('raw', json.dumps(line))
                            self.send_message(report)
        else:
            self.logger.error(response.text)


BOT = HoneypotCollectorBot
