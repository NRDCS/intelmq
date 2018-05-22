# -*- coding: utf-8 -*-

"""
Vxstream sandbox report parser bot
Parses report and creates IntelMQ event.

Parameters:
    conf_file: string
    provider: string
    classification: string
"""

import json, datetime
from intelmq.lib import utils
from intelmq.lib.bot import Bot


class SandboxParserBot(Bot):

    def process(self):
        classification_type = self.parameters.classification
        activity = self.parameters.activity # network|sandbox
        report = self.receive_message()
        raw_report = utils.base64_decode(report.get('raw'))
        sandbox_event = json.loads(raw_report)

        if activity == 'network':
            # If one element when it is a list else a dictionary
            if sandbox_event['analysis']['runtime']['network']['hosts']:
                if type(sandbox_event['analysis']['runtime']['network']['hosts']['host']) is list:
                    for key, value in sandbox_event['analysis']['runtime']['network']['hosts'].items():
                        for v in value:
                            event = self.new_event(report)
                            event.add('event_description.text', 'Malicious code network activity')
                            event.add('malware.hash.md5', sandbox_event['analysis']['general']['digests']['md5'])
                            event.add('malware.hash.sha1', sandbox_event['analysis']['general']['digests']['sha1'])
                            event.add('malware.hash.sha256', sandbox_event['analysis']['general']['digests']['sha256'])
                            event.add('source.ip', v['address'])
                            event.add('source.port', v['port'])
                            event.add('classification.type', classification_type)
                            self.send_message(event)

                if type(sandbox_event['analysis']['runtime']['network']['hosts']['host']) is dict:
                    for key, value in sandbox_event['analysis']['runtime']['network']['hosts'].items():
                        event = self.new_event(report)
                        event.add('event_description.text', 'Malicious code network activity')
                        event.add('malware.hash.md5', sandbox_event['analysis']['general']['digests']['md5'])
                        event.add('malware.hash.sha1', sandbox_event['analysis']['general']['digests']['sha1'])
                        event.add('malware.hash.sha256', sandbox_event['analysis']['general']['digests']['sha256'])
                        event.add('source.ip', value['address'])
                        event.add('source.port', value['port'])
                        event.add('classification.type', classification_type)
                        self.send_message(event)

            if sandbox_event['analysis']['runtime']['network']['domains']:
                if type(sandbox_event['analysis']['runtime']['network']['domains']['domain']) is list:
                    for key, value in sandbox_event['analysis']['runtime']['network']['domains'].items():
                        for v in value:
                            event = self.new_event(report)
                            event.add('event_description.text', 'Malicious code network activity')
                            event.add('malware.hash.md5', sandbox_event['analysis']['general']['digests']['md5'])
                            event.add('malware.hash.sha1', sandbox_event['analysis']['general']['digests']['sha1'])
                            event.add('malware.hash.sha256', sandbox_event['analysis']['general']['digests']['sha256'])
                            event.add('source.fqdn', v['db'])
                            event.add('classification.type', classification_type)
                            self.send_message(event)

                if type(sandbox_event['analysis']['runtime']['network']['domains']['domain']) is dict:
                    for key, value in sandbox_event['analysis']['runtime']['network']['domains'].items():
                        event = self.new_event(report)
                        event.add('event_description.text', 'Malicious code network activity')
                        event.add('malware.hash.md5', sandbox_event['analysis']['general']['digests']['md5'])
                        event.add('malware.hash.sha1', sandbox_event['analysis']['general']['digests']['sha1'])
                        event.add('malware.hash.sha256', sandbox_event['analysis']['general']['digests']['sha256'])
                        event.add('source.fqdn', value['db'])
                        event.add('classification.type', classification_type)
                        self.send_message(event)

        if activity == 'sandbox':
            event = self.new_event(report)
            if 'sample' in sandbox_event['analysis']['general']:
                event.add('extra.filename', sandbox_event['analysis']['general']['sample'])
            if 'target_url' in sandbox_event['analysis']['general']['controller']:
                event.add('extra.url', sandbox_event['analysis']['general']['controller']['target_url'])
            if 'threatscore' in sandbox_event['analysis']['final']['verdict']:
                event.add('extra.threatscore', sandbox_event['analysis']['final']['verdict']['threatscore'])
            if 'overallconfidence' in sandbox_event['analysis']['final']['confidence']:
                event.add('extra.confidence', sandbox_event['analysis']['final']['confidence']['overallconfidence'])
            if 'has_carved_files' in sandbox_event['analysis']['final']['characteristics']:
                event.add('extra.characteristics.carved_files', sandbox_event['analysis']['final']['characteristics']['has_carved_files'])
            if 'has_network_traffic' in sandbox_event['analysis']['final']['characteristics']:
                event.add('extra.characteristics.network_traffic', sandbox_event['analysis']['final']['characteristics']['has_network_traffic'])
            if 'threat' in sandbox_event['analysis']['final']['business_threats']:
                if 'display' in sandbox_event['analysis']['final']['business_threats']['threat']:
                    event.add('extra.business_threats', sandbox_event['analysis']['final']['business_threats']['threat']['display'])
            event.add('malware.hash.md5', sandbox_event['analysis']['general']['digests']['md5'])
            event.add('malware.hash.sha1', sandbox_event['analysis']['general']['digests']['sha1'])
            event.add('malware.hash.sha256', sandbox_event['analysis']['general']['digests']['sha256'])
            self.send_message(event)

        self.acknowledge_message()


BOT = SandboxParserBot
