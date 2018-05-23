# -*- coding: utf-8 -*-

"""
T-POT honeypot collector bot to generate alerts
Queries ElasticSearch to get events from T-POT honeypots.
Generates alerts if alert baseline is higher than normal.

Parameters:
    query_file: string
    baseline_time: int
    check_time: int
    check_rate: int
    classification: string
"""

import requests, json
from intelmq.lib.bot import CollectorBot


class HoneypotAlertBot(CollectorBot):

    def sensor_statistics(self, elk_query):
        sensor_stats = {}
        elk_url = self.parameters.elk_url
        headers = {'Content-Type': 'application/json'}
        response = requests.get(elk_url, data=json.dumps(elk_query), headers=headers, verify=False)
        if response.status_code == 200 and 'took' in response.text:
            report = json.loads(response.text)
            aggs = next(iter(report['aggregations']))
            for item in report['aggregations'][aggs]['buckets']:
                for key, value in item.items():
                    if type(value) == dict:
                        if value['buckets']: # Check if bucket has values
                            for attr in value['buckets']:
                                if attr['key'] in sensor_stats:
                                    sensor_stats[attr['key']] += attr['doc_count'] # Adding values if its a known sensor
                                else:
                                    sensor_stats[attr['key']] = attr['doc_count'] # Starting a counter for previously not observed sensor
            return sensor_stats
        else:
            self.logger.error(response.text)

    def process(self):
        query_file = self.parameters.query_file
        baseline_time = self.parameters.baseline_time
        check_time = self.parameters.check_time
        check_rate = self.parameters.check_rate
        classification = self.parameters.classification

        # NOW - (check_time + baseline_time)
        elk_query = json.load(open(query_file))
        for item in elk_query['query']['bool']['must']:
            if 'range' in item:
                for key, value in item.items():
                    for k, v in value.items():
                        v['gte'] = 'now-' + str(check_time + baseline_time) + 'h'
                        v['lte'] = 'now-' + str(check_time) + 'h'

        basecheck_stats = self.sensor_statistics(elk_query)
        if basecheck_stats:
            for key, value in basecheck_stats.items():
                basecheck_stats[key] = value / (baseline_time * 3600) # Alert average per second for baseline time

        # NOW - check_time
        elk_query = json.load(open(query_file))
        for item in elk_query['query']['bool']['must']:
            if 'range' in item:
                for key, value in item.items():
                    for k, v in value.items():
                        v['gte'] = 'now-' + str(check_time) + 'h'
                        v['lte'] = 'now'

        check_stats = self.sensor_statistics(elk_query)
        if check_stats:
            for key, value in check_stats.items():
                check_stats[key] = value / (check_time * 3600) # Alert average per second for check time

        if basecheck_stats and check_stats:
            self.logger.info('Honeypot to IntelMQ processing started')
            for key, value in basecheck_stats.items():
                if key in check_stats:
                    if check_stats[key] / basecheck_stats[key] >= check_rate:
                        line = {}
                        line.update({'extra.sensor.name': key})
                        line.update({'extra.sensor.rate': round(check_stats[key] / basecheck_stats[key], 2)})
                        line.update({'classification.type': classification})
                        report = self.new_report()
                        report.add('raw', json.dumps(line))
                        self.send_message(report)


BOT = HoneypotAlertBot
