# -*- coding: utf-8 -*-

"""
Vxstream sandbox report collector bot
Queries VxStream malware sandbox for last n days.
Parses report and queries sandbox for each observed hash.
Checks if there are matching IP addresses, domains.
Removes lines which have excludeIPs or excludeDomains values.

Parameters:
    search_conf: string
    sandbox_url: string
    sandbox_api_key: string
    sandbox_api_secret: string
    days: int
    minimum_threatscore: int
"""

import requests, json, ipaddress
from intelmq.lib.bot import CollectorBot


class SandboxCollectorBot(CollectorBot):


    def process(self):
        search_conf = self.parameters.conf_file  # search.json
        sandbox_url = self.parameters.sandbox_url  # http://sandbox.cert
        sandbox_api_key = self.parameters.sandbox_api_key  # cqphgb6yh3k8wskggskw40wcg
        sandbox_api_secret = self.parameters.sandbox_api_secret  # 965e9128e3c756a069cc480d7f833ce196bad07d1b724fa4
        days = self.parameters.days  # Number of days to query sandbox reports /api/feed/:days
        minimum_threatscore = self.parameters.minimum_threatscore

        search = json.load(open(search_conf))
        hashes = []
        excludeIPs = []
        excludeDomains = []

        # Querying attributes from sandbox
        s = requests.Session()
        s.auth = (sandbox_api_key, sandbox_api_secret)
        s.post(sandbox_url, headers={'Content-Type': 'application/json', 'Accept': 'application/json', 'User-Agent': 'Falcon Sandbox'})
        response = s.get(sandbox_url + '/api/feed/' + str(days), headers={'Content-Type': 'application/json', 'Accept': 'application/json', 'User-Agent': 'Falcon Sandbox'})
        if response.status_code == 200:
            self.logger.info('Sandbox to IntelMQ processing started')
            m1 = 0
            data = response.json()
            if data['count'] > 0:
                if len(search) > 0:
                    # Adding exclude IPs and domains to lists
                    for i in range(0, len(search)):
                        excludeIPs = []
                        excludeDomains = []
                        if 'excludeIPs' in search[i]:
                            with open(search[i]['excludeIPs'], 'r') as file:
                                for line in file:
                                    excludeIPs.append(line.strip('\n'))
                                file.close()
                        if 'excludeDomains' in search[i]:
                            with open(search[i]['excludeDomains'], 'r') as file:
                                for line in file:
                                    excludeDomains.append(line.strip('\n'))
                                file.close()
                    for i in range(0, len(search)):
                        # Filtering by provided IP addresses (host) and domains (domain)
                        count = len(search[i])
                        if 'host' in search[i] or 'domain' in search[i]:
                            for attr in data['data']:
                                if 'host' in search[i]:
                                    if 'hosts' in attr:
                                        for host in attr['hosts']:
                                            # ipaddress.ip_address('192.168.0.1') in ipaddress.ip_network('192.168.0.0/24')
                                            if ipaddress.ip_address(host) in ipaddress.ip_network(search[i]['host']):
                                                m1 = +1

                                if 'domain' in search[i]:
                                    if 'domains' in attr and search[i]['domain'] in attr['domains']:
                                        m1 = +1
                                if m1 == count:
                                    temp = {'sha256': attr['sha256'], 'environmentid': attr['environmentId']}
                                    hashes.append(temp)
                                m1 = 0
                        file = None
                        # Filtering by provided includeIPs, includeDomains file content
                        if 'includeIPs' in search[i]:
                            file = open(search[i]['includeIPs'], 'r')
                        if 'includeDomains' in search[i]:
                            file = open(search[i]['includeDomains'], 'r')
                        if file != None and file.closed == False:
                            lines = file.readlines()
                            file.close()
                            for attr in data['data']:
                                for line in lines:
                                    try:
                                        if 'hosts' in attr:
                                            for host in attr['hosts']:
                                                if ipaddress.ip_address(host) in ipaddress.ip_network(line.strip('\n')):
                                                    temp = {'sha256': attr['sha256'], 'environmentid': attr['environmentId']}
                                                    hashes.append(temp)
                                    except:
                                        if 'domains' in attr and line.strip('\n') in attr['domains']:
                                            temp = {'sha256': attr['sha256'], 'environmentid': attr['environmentId']}
                                            hashes.append(temp)
                # Sandbox hashes without filtering
                else:
                    for attr in data['data']:
                        temp = {'sha256': attr['sha256'], 'environmentid': attr['environmentId']}
                        hashes.append(temp)

                # Remove duplicate values
                unique = []
                seen = set()
                for item in hashes:
                    if item['sha256'] not in seen:
                        unique.append(item)
                        seen.add(item['sha256'])
                hashes = unique

                if len(hashes) > 0:
                    for hash in hashes:
                        # Parsing each sandbox event
                        params = {'apikey': sandbox_api_key, 'secret': sandbox_api_secret, 'environmentId': hash['environmentid'], 'type': 'json'}
                        reportUrl = sandbox_url + '/api/result/' + hash['sha256']
                        response = requests.get(reportUrl, headers={'User-agent': 'VxStream Sandbox'}, params=params)
                        data = json.loads(response.text)
                        # IntelMQ report creation
                        if 'response_code' not in data:
                            if int(data['analysis']['final']['verdict']['threatscore']) >= minimum_threatscore:
                                # Removing excludeIPs, excludeDomains content
                                if data['analysis']['runtime']['network']['hosts']:
                                    if type(data['analysis']['runtime']['network']['hosts']['host']) is list:
                                        for key, value in data['analysis']['runtime']['network']['hosts'].items():
                                            item = 0
                                            for v in value:
                                                for IP in excludeIPs:
                                                    if ipaddress.ip_address(v['address']) in ipaddress.ip_network(IP):
                                                        data['analysis']['runtime']['network']['hosts'].pop(item)
                                                        break
                                                item += 1
                                    if type(data['analysis']['runtime']['network']['hosts']['host']) is dict:
                                        for key, value in data['analysis']['runtime']['network']['hosts'].items():
                                            item = 0
                                            for IP in excludeIPs:
                                                if ipaddress.ip_address(value['address']) in ipaddress.ip_network(IP):
                                                    data['analysis']['runtime']['network']['hosts'].pop(item)
                                                    break
                                            item += 1
                                if data['analysis']['runtime']['network']['domains']:
                                    if type(data['analysis']['runtime']['network']['domains']['domain']) is list:
                                        for key, value in data['analysis']['runtime']['network']['domains'].items():
                                            item = 0
                                            for v in value:
                                                for domain in excludeDomains:
                                                    if domain in v['db']:
                                                        data['analysis']['runtime']['network']['domains'].pop(item)
                                                        break
                                                item += 1
                                    if type(data['analysis']['runtime']['network']['domains']['domain']) is dict:
                                        for key, value in data['analysis']['runtime']['network']['domains'].items():
                                            item = 0
                                            for domain in excludeDomains:
                                                if domain in value['address']:
                                                    data['analysis']['runtime']['network']['domains'].pop(item)
                                                    break
                                            item += 1

                                report = self.new_report()
                                report.add('raw', json.dumps(data))
                                self.send_message(report)
                        else:
                            self.logger.error(response.text)
        else:
            self.logger.error(response.text)


BOT = SandboxCollectorBot
