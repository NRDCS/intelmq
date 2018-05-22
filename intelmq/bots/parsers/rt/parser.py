# -*- coding: utf-8 -*-
"""
The source provides a JSON file with a dictionary of ticket field/customfiel name and value pairs
"""

import json

from datetime import datetime
from dateutil import tz

from intelmq.lib import utils
from intelmq.lib.bot import Bot

class RTParserBot(Bot):

    field_mapping = {'CF.{Category}': 'extra.incident_category',
                     'CF.{Classification}': 'classification.taxonomy',
                     'CF.{Description}': 'event_description.text',
                     'CF.{Incident time}': 'time.source',
                     'CF.{Incident Type}': 'classification.type',
                     }

    value_mapping = {'Scanning': 'scanner',
                     'Sniffing': 'compromised',
                     'Man in the middle': 'compromised',
                     'Phishing': 'phishing',
                     'Exploitation of vulnerability': 'exploit',
                     'Account compromise': 'compromised',
                     'Undetermined': 'other',
                     'Exploitation of vulnerability': 'exploit',
                     'Login attempts': 'test',
                     'Infected': 'malware',
                     'Distribution': 'malware configuration',
                     'C&C': 'c&c',
                     'DoS': 'ddos',
                     'Sabotage': 'other',
                     'Other': 'other',
                     'System failure': 'other',
                     'Human error': 'other',
                     'Natural phenomena': 'other',
                     '3rd party failure': 'other',
                     'Copyright': 'other',
                     'Porn': 'other',
                     'Personal data': 'other',
                     'Spam': 'spam',
                     'Criminal': 'other',
                     'Fraud': 'other',
                     'Hatred / mocking': 'other',
                     'Misconfiguration': 'other',
                     'SSL / TLS': 'other',
                     'Outdated OS': 'vulnerable service',
                     'Outdated firmware': 'vulnerable service',
                     'Outdated application': 'vulnerable service',
                     'Awareness': 'other',
                     'Consultation': 'other',
                     'Maintenance': 'other',
                     'Other': 'other'
                    }

    unique_field_mapping = {'CF.{IP}': 'source.ip',
                            'CF.{URLs}': 'source.url',
                            }

    """
    Configuration parameters:
      fields_to_collect - list of field names to collect from ticket data
    """
    def init(self):
        self.fields_to_collect = []

        if self.parameters.fields_to_collect:
           self.fields_to_collect = [f.strip() for f in self.parameters.fields_to_collect.split(',')]

    def process(self):
        report = self.receive_message()
        event = self.new_event(report)

        ticket_json = utils.base64_decode(report.get("raw"))

        # try to parse a JSON object
        ticket = json.loads(ticket_json)

        event.add("raw", report.get("raw"), sanitize=False)
        event.add("rtir_id", int(ticket['id'].split('/')[1]))

        self.logger.debug('Process ticket %s.', int(ticket['id'].split('/')[1]))

        event = self.__extract_common_event(event, ticket)
        """
        Create distinct event for every field value in unique_field_mapping
        """
        for rt_field, intelmq_field in self.unique_field_mapping.items():
            # Check if value is not empty
            if rt_field in ticket and len(ticket[rt_field]) > 0:
                # There might be multiple values, extract them and create separate events for each
                values = ticket[rt_field].split(',')
                for value in values:
                    temp_event = event.copy()
                    temp_event.add(intelmq_field, value)
                    self.send_message(temp_event)

        self.acknowledge_message()

    """
    Extract common ticket fields that every event created from this ticket should have. 
    
    Iterate every ticket field and check if it is mapped in field_mapping property or
    required to be collected with fields_to_collect configuration. Both ticket fields and 
    CustomFields (CF.{<field_name>}) are checked.
    """
    def __extract_common_event(self, event, ticket):
        self.logger.info('Extracting common event from ticked data')

        for rt_field in ticket:
            if type(ticket[rt_field]) is not str or len(ticket[rt_field]) == 0:
               continue
            if rt_field in self.unique_field_mapping:
               continue

            if rt_field in self.field_mapping:
               field = self.field_mapping[rt_field]

               if field == 'time.source':
                  value = str(self.__format_date(ticket[rt_field]))
               elif field == 'classification.type':
                  value = self.value_mapping[ticket[rt_field]]
                  event.add('extra.incident_type', ticket[rt_field])
               else:
                  value = ticket[rt_field].replace("'", "")

               event.add(field, value)
            else:
               for field in self.fields_to_collect:
                   if field.lower() == rt_field.lower() or self.__field_name_as_customfield(field) == rt_field.lower():
                      event.add('extra.' + field.lower().replace(" ", "_"), ticket[rt_field].replace("'", ""))

        return event
    
    def __field_name_as_customfield(self, field):
        return 'CF.{{0}}'.format(field).lower()

    def __format_date(self, date_string):
        date_obj = datetime.strptime(date_string, '%Y-%m-%d %H:%M:%S')

        return date_obj.replace(tzinfo=tz.tzutc())

BOT = RTParserBot
