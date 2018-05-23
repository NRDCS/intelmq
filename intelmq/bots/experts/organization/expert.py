# -*- coding: utf-8 -*-

"""
Organization name expert bot
Adds an organization name, sector and id to source or destination IP event.

Parameters:
    api_url: string
    api_user: string
    api_pass: string
"""

import requests, json
from intelmq.lib.bot import Bot


class OrganizationExpertBot(Bot):

    def process(self):
        api_url = self.parameters.api_url
        api_user = self.parameters.api_user
        api_pass = self.parameters.api_pass

        self.logger.info('Organization name expert bot started')
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}

        event = self.receive_message()
        # If organisation name exists - adds sector and ID
        if 'destination.organization.name' in event and 'destination.organization.sector' not in event:
            req_body = {'with_deleted': True, 'search': str(event['destination.organization.name']), 'user_name': api_user, 'password': api_pass}
            response = requests.post(api_url + '/api/organisations-search', data=json.dumps(req_body), headers=headers, verify=False)
            by_name = response.json()
            if 'message' not in by_name:
                for line in by_name['data']:
                    event.add('destination.organization.sector', line['sector_type']['name'])
                    event.add('destination.organization.id', line['public_id'])

        if 'source.organization.name' in event and 'source.organization.sector' not in event:
            req_body = {'with_deleted': True, 'search': str(event['source.organization.name']), 'user_name': api_user, 'password': api_pass}
            response = requests.post(api_url + '/api/organisations-search', data=json.dumps(req_body), headers=headers, verify=False)
            by_name = response.json()
            if 'message' not in by_name:
                for line in by_name['data']:
                    event.add('source.organization.sector', line['sector_type']['name'])
                    event.add('source.organization.id', line['public_id'])

        # If IP is only value, then queries to get organisation ID
        if 'destination.ip' in event and 'destination.organization.name' not in event and 'destination.organization.sector' not in event:
            req_body = {'user_name': api_user, 'password': api_pass}
            response = requests.post(api_url + '/api/organisations-search/by-ip/' + str(event['destination.ip']), data=json.dumps(req_body), headers=headers, verify=False)
            by_ip = response.json()
            if 'message' not in by_ip:
                org_id = by_ip['data']['id']
                # Query to get organisation name and sector using organisation ID
                response = requests.post(api_url + '/api/organisations/' + str(org_id), data=json.dumps(req_body), headers=headers, verify=False)
                data = response.json()
                if 'message' not in data:
                    event.add('destination.organization.name', data['data']['name'])
                    event.add('destination.organization.sector', data['data']['sector_type']['name'])
                    event.add('destination.organization.id', data['data']['public_id'])

        if 'source.ip' in event and 'source.organization.name' not in event and 'source.organization.sector' not in event:
            req_body = {'user_name': api_user, 'password': api_pass}
            response = requests.post(api_url + '/api/organisations-search/by-ip/' + str(event['source.ip']), data=json.dumps(req_body), headers=headers, verify=False)
            by_ip = response.json()
            if 'message' not in by_ip:
                org_id = by_ip['data']['id']
                response = requests.post(api_url + '/api/organisations/' + str(org_id), data=json.dumps(req_body), headers=headers, verify=False)
                data = response.json()
                if 'message' not in data:
                    event.add('source.organization.name', data['data']['name'])
                    event.add('source.organization.sector', data['data']['sector_type']['name'])
                    event.add('source.organization.id', data['data']['public_id'])

        self.send_message(event)
        self.acknowledge_message()


BOT = OrganizationExpertBot
