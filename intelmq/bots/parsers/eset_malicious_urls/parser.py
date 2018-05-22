# -*- coding: utf-8 -*-
"""
ESET parser bot parses JSON attachments

"""
import json
from intelmq.lib import utils
from intelmq.lib.bot import Bot




class ESETmaliciousURLs(Bot):
	def process(self):
		report = self.receive_message()
		raw_report = utils.base64_decode(report.get("raw"))
		key_map = {
			'url': 'source.url',
			'first_seen': 'time.source',
			'sha1': 'malware.hash.sha1',
			'infection': 'malware.name',
		}
		for row in raw_report.splitlines():
			row = row.strip()
			if row == "":
				continue
			json_row = json.loads(row)
			event = self.new_event(report)
			
			for item in json_row:
				if item in key_map:
					if json_row.get(item, None):
						event_key = key_map[item]
						if item == 'first_seen':
							event.add(event_key, json_row[item] + ' UTC')
						else:
							event.add(event_key, json_row[item])
			event.add('classification.type', 'malware')
			event.add('raw', row)
			
			self.send_message(event)
		self.acknowledge_message()


BOT = ESETmaliciousURLs