# -*- coding: utf-8 -*-
"""
Request Tracker output bot

Creates a ticket in the specified queue
Parameters:
URI, user, password, queue
"""

from intelmq.lib.bot import Bot
try:
    import rt
except ImportError:
    rt = None
    
class RTOutputBot(Bot):

    # Some event attributes are mapped to ticket custom fields 
    CF_mapping = {'Description': 'event_description.text',
#        'classification.taxonomy': 'Classification',
#        'classification.type': 'Incident Type',
        'source.ip': 'IP',
        'Status': 'Incident Type',
        'source.url': 'URLs',
        'malware.hash.md5': 'Hashes',
        'time.source': 'Incident time',
        'source.organisation.name': 'Customer'
    }
    # special mapping for Incident Type values
    # Incident ticket has CF Incident type 
    # (subtype of the main incident classification).
    # Values has to be properly mapped
    Type_mapping = {
        'backdoor': ['Malware', 'Infected'],
        'blacklist':    ['Malware', 'Infected'],
        'botnet drone': ['Malware', 'Infected'],
        'brute-force':  ['Intrusion attempt', 'Login attempts'],
        'c&c':  ['Malware', 'C&C'],
        'compromised':  ['Intrusion', 'Account compromise'],
        'ddos': ['Availability','DoS'],
        'defacement':   ['Intrusion', 'Undetermined'],
        'dga domain':   ['Intrusion', 'Undetermined'],
        'dropzone': ['Malware', 'Distribution'],
        'exploit':  ['Intrusion attempt','Exploitation of vulnerability'],
        'ids alert':    ['Intrusion attempt','Exploitation of vulnerability'],
        'leak': ['Internet content issue','Personal data'],
        'malware':  ['Malware', 'Infected'],
        'malware configuration':    ['Malware', 'Distribution'],
        'other':    ['Other', 'Other'],
        'phishing': ['Information gathering','Phishing'],
        'proxy':    ['Cyberthreat','Misconfiguration'],
        'ransomware':   ['malware', 'Infected'],
        'scanner':  ['Information gathering', 'Scanning'],
        'spam': ['Internet content issue','Spam'],
        'test': ['Other','Other'],
        'tor':  ['Other','Other'],
        'unknown':  ['Other','Other'],
        'vulnerable service':   ['Cyberthreat','Outdated application']
    }
    def init(self):
        if rt is None:
            self.logger.error('Could not import rt. Please install it.')
            self.stop()
            
    def process(self):
        event = self.receive_message()
        del event['raw']
        RT = rt.Rt(self.parameters.uri, verify_cert=self.parameters.verify_cert)
        if not RT.login(self.parameters.user,
                   self.parameters.password):
            raise ValueError('Login failed.')          
        kwargs = {}
        # we make subject in form of "Incident: IP"
        subject = 'incident: ' + event['source.ip']
        content = ""
        classification = ""
        incident_type = ""
        if event['classification.type']:
            classification, incident_type = self.Type_mapping[event['classification.type']]
            self.logger.debug("Classification assigned: %s, %s", classification, incident_type)
            kwargs["CF_Classification"] = classification
            kwargs["CF_Incident type"] = incident_type
            
        for key, value in event.items():
            # Add all event attributes to the body of the incident ticket
            content += key + ": " + str(value) + "\n"
            # Add some (mapped) event attributes to the Custom Fields of the ticket
            if self.CF_mapping.get(key):
                # In case we have event attribute which is mapped to the Incident Type CF,
                # we also do value mapping
                #if self.CF_mapping.get(key) == 'Incident Type' and self.Type_mapping.get(value):
                #    str_value = self.Type_mapping.get(value)
                #else:
                str_value = str(value)
                kwargs["CF_" + self.CF_mapping.get(key)] = str_value
                self.logger.debug("Added argument line CF_%s: %s", self.CF_mapping.get(key), kwargs["CF_" + self.CF_mapping.get(key)])
        self.logger.debug("RT ticket subject: %s", subject)
        ticket_id = RT.create_ticket(Queue=self.parameters.queue, Subject=subject, Text=content, **kwargs)
        if ticket_id > -1:
            self.logger.info("RT ticket created: %i", ticket_id)
        else:
            self.logger.error("Failed to create RT ticket")
        self.acknowledge_message()

BOT = RTOutputBot
