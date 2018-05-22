# -*- coding: utf-8 -*-

"""
MISP output bot
Creates MISP event and attributes from IntelMQ data.

Parameters:
    misp_api_key: string
    misp_url: string
    tags: string, example: ["TLP:Amber","CERT-LT:sandbox"]
"""
"""
IntelMQ - MISP attribute mapping
destination.ip: Network activity, ip-dst
destination.url: Network activity, url
destination.port: Network activity, ip-dst|port
source.ip: Network activity, ip-src
source.url: Network activity, url
source.port: Network activity, ip-src|port
event_description.text: Network activity, text
event_description.url: External analysis, url
malware.hash.md5: Payload delivery, md5
malware.hash.sha1: Payload delivery, sha1
malware.hash.sha256: Payload delivery, sha256
"""

from intelmq.lib.bot import Bot
import requests, json


class MISPOutputBot(Bot):


    def process(self):
        misp_api_key = self.parameters.misp_api_key  # MISP API key
        misp_url = self.parameters.misp_url  # MISP URL
        tags = self.parameters.tags  # List of MISP tags
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json', 'Authorization': misp_api_key}

        data = self.receive_message()
        event_json = {'response': {'Event': {'date': data['time.observation'].split('T')[0], 'info': data['feed.provider'], 'distribution': 0, 'published': 1, 'Org': {'name': 'CERT.LT'}, 'Orgc': {'name': 'CERT.LT'}, 'Attribute': [], 'threat_level_id': 4}}}

        # Adding attributes from IntelMQ event
        if 'destination.ip' in data:
            event_json['response']['Event']['Attribute'].append({'category': 'Network activity', 'type': 'ip-dst', 'value': data['destination.ip'], 'distribution': 0})
        if 'destination.url' in data:
            event_json['response']['Event']['Attribute'].append({'category': 'Network activity', 'type': 'url', 'value': data['destination.url'], 'distribution': 0})
        if 'destination.port' in data:
            event_json['response']['Event']['Attribute'].append({'category': 'Network activity', 'type': 'ip-dst|port', 'value': data['destination.port'], 'distribution': 0})
        if 'source.ip' in data:
            event_json['response']['Event']['Attribute'].append({'category': 'Network activity', 'type': 'ip-src', 'value': data['source.ip'], 'distribution': 0})
        if 'source.url' in data:
            event_json['response']['Event']['Attribute'].append({'category': 'Network activity', 'type': 'url', 'value': data['source.url'], 'distribution': 0})
        if 'source.port' in data:
            event_json['response']['Event']['Attribute'].append({'category': 'Network activity', 'type': 'ip-src|port', 'value': data['source.port'], 'distribution': 0})
        if 'event_description.text' in data:
            event_json['response']['Event']['Attribute'].append({'category': 'External analysis', 'type': 'text', 'value': data['event_description.text'], 'distribution': 0})
        if 'event_description.url' in data:
            event_json['response']['Event']['Attribute'].append({'category': 'External analysis', 'type': 'url', 'value': data['event_description.url'], 'distribution': 0})
        if 'malware.hash.md5' in data:
            event_json['response']['Event']['Attribute'].append({'category': 'Payload delivery', 'type': 'md5', 'value': data['malware.hash.md5'], 'distribution': 0})
        if 'malware.hash.sha1' in data:
            event_json['response']['Event']['Attribute'].append({'category': 'Payload delivery', 'type': 'sha1', 'value': data['malware.hash.sha1'], 'distribution': 0})
        if 'malware.hash.sha256' in data:
            event_json['response']['Event']['Attribute'].append({'category': 'Payload delivery', 'type': 'sha256', 'value': data['malware.hash.sha256'], 'distribution': 0})

        event_tags = []
        for tag in tags:
            event_tags.append({'name': tag})
        event_json['response']['Event']['Tag'] = event_tags

        # Creation of MISP event
        response = requests.post(misp_url + '/events', data=json.dumps(event_json), headers=headers, verify=False)
        if response.status_code != 200:
            self.logger.error(response.status_code, response.text)
        else:
            self.acknowledge_message()


BOT = MISPOutputBot
