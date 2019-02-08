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

import urllib3

class OrganizationExpertBot(Bot):

    def process(self):
        api_url = self.parameters.api_url
        api_user = self.parameters.api_user
        api_pass = self.parameters.api_pass

        self.logger.info('Organization name expert bot started')
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}

        urllib3.disable_warnings()

        event = self.receive_message()
        # If organisation name exists - adds sector and ID
        if 'destination.organization.name' in event and 'destination.organization.sector' not in event:
            req_body = {'with_deleted': True, 'search': str(event['destination.organization.name']), 'user_name': api_user, 'password': api_pass}
            response = requests.post(api_url + '/api/organisations-search', data=json.dumps(req_body), headers=headers, verify=False)
            by_name = response.json()
            if 'message' not in by_name:
                for line in by_name['data']:
                    event.add('destination.organization.sector', line['sector_type']['name'], overwrite=True)
                    event.add('destination.organization.id', line['public_id'], overwrite=True)

        if 'source.organization.name' in event and 'source.organization.sector' not in event:
            req_body = {'with_deleted': True, 'search': str(event['source.organization.name']), 'user_name': api_user, 'password': api_pass}
            response = requests.post(api_url + '/api/organisations-search', data=json.dumps(req_body), headers=headers, verify=False)
            by_name = response.json()
            if 'message' not in by_name:
                for line in by_name['data']:
                    event.add('source.organization.sector', line['sector_type']['name'], overwrite=True)
                    event.add('source.organization.id', line['public_id'], overwrite=True)

        # If IP is only value, then queries to get organisation ID
        if 'destination.ip' in event and 'destination.organization.name' not in event and 'destination.organization.sector' not in event:
            req_body = {'user_name': api_user, 'password': api_pass}
            response = requests.post(api_url + '/api/organisations-search/by-ip/' + str(event['destination.ip']), data=json.dumps(req_body), headers=headers, verify=False)
            by_ip = response.json()
            if 'message' not in by_ip and 'data' in by_ip and len(by_ip['data']) > 0:
                org_id = by_ip['data'][0]['id']
                # Query to get organisation name and sector using organisation ID
                response = requests.post(api_url + '/api/organisations/' + str(org_id), data=json.dumps(req_body), headers=headers, verify=False)
                data = response.json()
                if 'message' not in data:
                    event.add('destination.organization.name', data['data']['name'], overwrite=True)
                    event.add('destination.organization.sector', data['data']['sector_type']['name'], overwrite=True)
                    event.add('destination.organization.id', data['data']['public_id'], overwrite=True)

        if 'source.ip' in event and 'source.organization.name' not in event and 'source.organization.sector' not in event:
            self.logger.debug('Searching for: %s.', str(event['source.ip']))
            req_body = {'user_name': api_user, 'password': api_pass}
            response = requests.post(api_url + '/api/organisations-search/by-ip/' + str(event['source.ip']), data=json.dumps(req_body), headers=headers, verify=False)
            by_ip = response.json()
            self.logger.debug('Response JSON, by IP: %s.', response.text)
            if 'message' not in by_ip: 
                if 'data' in by_ip and len(by_ip['data']) > 0:
                    #self.logger.debug('Response JSON#0: %s.', str(by_ip['data'][0]))
                    #org_id = by_ip['data'][0]['id']
                    org_public_id = by_ip['data'][0]['public_id']
                    org_name = by_ip['data'][0]['name']
                    org_sector = by_ip['data'][0]['sector_type']['name']
                    event.add('source.organization.name', org_name, overwrite=True)
                    event.add('source.organization.sector', org_sector, overwrite=True)
                    event.add('source.organization.id', org_public_id, overwrite=True)
                    self.logger.debug('Information added: Organization=%s, Sector=%s, id=%s', org_name, org_sector, org_public_id)
                    #response = requests.post(api_url + '/api/organisations/' + str(org_id), data=json.dumps(req_body), headers=headers, verify=False)
                    #data = response.json()
                    #if 'message' not in data:
                    #    event.add('source.organization.name', data['data']['name'])
                    #    event.add('source.organization.sector', data['data']['sector_type']['name'])
                    #    event.add('source.organization.id', data['data']['public_id'])
                    #    self.logger.debug('Information added: Organization=%s, Sector=%s, id=%s',data['data']['name'],data['data']['sector_type']['name'],data['data']['public_id'])
                    #else:
                    #    self.logger.error('Error after json retrieval: %s', data['message'])
                else:
                    self.logger.debug('Did not retrieve data by IP')
                    # retrieving organization by ASN
                    if 'source.asn' in event:
                        req_body = {'with_deleted': True, 'user_name': api_user, 'password': api_pass, 'search': str(event['source.asn'])}
                        #self.logger.debug('Request query: %s', json.dumps(req_body))
                        response = requests.post(api_url + '/api/organisations-search', data=json.dumps(req_body), headers=headers, verify=False)
                        by_asn = response.json()
                        self.logger.debug('Response JSON, by ASN: %s', response.text)
                        if 'message' not in by_asn: 
                            if 'data' in by_asn and len(by_asn['data']) > 0:
                                #org_id = by_asn['data'][0]['id']
                                org_public_id = by_asn['data'][0]['public_id']
                                org_name = by_asn['data'][0]['name']
                                org_sector = by_asn['data'][0]['sector_type']['name']
                                event.add('source.organization.name', org_name, overwrite=True)
                                event.add('source.organization.sector', org_sector, overwrite=True)
                                event.add('source.organization.id', org_public_id, overwrite=True)
                                self.logger.debug('Information added: Organization=%s, Sector=%s, id=%s', org_name, org_sector, org_public_id)
                            else:
                                self.logger.debug('Did not retrieve data by ASN')
                        else:
                            if 'message' in by_asn:
                                self.logger.error('Error retrieving IP: %s', by_asn['message'])

            else:
                if 'message' in by_ip:
                    self.logger.error('Error retrieving IP: %s', by_ip['message'])


        self.send_message(event)
        self.acknowledge_message()


BOT = OrganizationExpertBot
