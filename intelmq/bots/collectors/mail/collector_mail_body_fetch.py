# -*- coding: utf-8 -*-
"""
Mail Body Fetch Collector bot

Regularly checks IMAP mailbox for new message with some subject
Takes all lines from the body which matches the regexp. 
Some software/hardware sents automatic reports with log 
information in the body. The bot fetches such log lines.
Parameters:
	"feed": feed name
	"provider": feed provider
	"folder": mailbox folder
	"mail_host": imap server
	"mail_password": mail password
	"mail_ssl": use IMAPS (true/false)
	"mail_user": username
	"rate_limit": mailbox check rate limit in sec.
	"subject_regex": Subject regexp to look in mailbox
	"line_regex": line regexp to look in the body

"""
import re
import io
import imaplib
import requests

try:
    import imbox
except ImportError:
    imbox = None

from intelmq.lib.bot import CollectorBot
from intelmq.lib.utils import decode


class MailBodyFetchCollectorBot(CollectorBot):

    def init(self):
        if imbox is None:
            self.logger.error('Could not import imbox. Please install it.')
            self.stop()

        # Build request
        self.set_request_parameters()



    def connect_mailbox(self):
        self.logger.debug("Connecting to %s.", self.parameters.mail_host)
        mailbox = imbox.Imbox(self.parameters.mail_host,
                              self.parameters.mail_user,
                              self.parameters.mail_password,
                              self.parameters.mail_ssl)
        return mailbox

    def process(self):
        mailbox = self.connect_mailbox()
        emails = mailbox.messages(folder=self.parameters.folder, unread=True,
                                  sent_to=getattr(self.parameters, "sent_to", None),
                                  sent_from=getattr(self.parameters, "sent_from", None))

        if emails:
            for uid, message in emails:

                if (self.parameters.subject_regex and
                        not re.search(self.parameters.subject_regex,
                                      re.sub("\r\n\s", " ", message.subject))):
                    self.logger.debug("Message with date %s skipped because subject %r does not match.",
                                      message.date, message.subject)
                    continue

                erroneous = False  # If errors occurred this will be set to true.

                #self.logger.debug("Message keys %s.", ",".join(message.keys()))

                for body in message.body['plain']:
                    for line in body.splitlines():
                        match = re.search(self.parameters.line_regex, str(line))
                        if match:
                            line = match.group()
                            # strip leading and trailing spaces, newlines and
                            # carriage returns
                            line = line.strip()
                            report = self.new_report()
                            report.add("raw", decode(line))
                            self.send_message(report)

                try:
                    mailbox.mark_seen(uid)
                except imaplib.abort:
                    # Disconnect, see https://github.com/certtools/intelmq/issues/852
                    mailbox = self.connect_mailbox()
                    mailbox.mark_seen(uid)

                if not erroneous:
                    self.logger.info("Email report read.")
                else:
                    self.logger.error("Email report read with errors, the report was not processed.")
        else:
            self.logger.debug("No unread mails to check.")
        mailbox.logout()


BOT = MailBodyFetchCollectorBot
