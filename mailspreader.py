#!/usr/bin/env pypy3

import argparse
import configparser
import email
import email.utils
import imaplib
import logging
import os.path
import smtplib
import sys
import traceback


class MailSpreader(object):
    """The class is basic script for sending a mails to \
    multiply destinantions"""

    # sections from the configuration file

    CONFIG_SECTION_INPUT_SERVER = "INPUT-SERVER"
    CONFIG_SECTION_MAIN = "MAIN"
    CONFIG_SECTION_SEND_SERVER = "SEND-SERVER"
    CONFIG_SECTION_STORE_SERVER = "STORE-SERVER"

    # default values for some config fields

    CONFIG_DEFAULT_ACCEPTED_MAIL_ADDRESSES = None
    CONFIG_DEFAULT_CHECK_ON_RETURN_PATH = True
    CONFIG_DEFAULT_CUSTOM_HEADER = ""
    CONFIG_DEFAULT_CUSTOM_HEADER_VALUE = ""
    CONFIG_DEFAULT_DELETE_AFTER_PROCESSING = False
    CONFIG_DEFAULT_MAILBOX = None
    CONFIG_DEFAULT_MARK_AS_SEEN_AFTER_PROCESSING = True
    CONFIG_DEFAULT_REPLY_TO = None
    CONFIG_DEFAULT_SEARCH_FILTER = 'NEW'

    # fields from the config file

    CONFIG_FIELD_ACCEPTED_MAIL_ADDRESSES = 'accepted_mail_addresses'
    CONFIG_FIELD_CHECK_ON_RETURN_PATH = 'check_on_return_path'
    CONFIG_FIELD_CUSTOM_HEADER = 'custom_header'
    CONFIG_FIELD_CUSTOM_HEADER_VALUE = 'custom_header_value'
    CONFIG_FIELD_DELETE_AFTER_PROCESSING = 'delete_after_processing'
    CONFIG_FIELD_HOST = 'host'
    CONFIG_FIELD_LOGFIlE = 'logfile'
    CONFIG_FIELD_MAILBOX = 'mailbox'
    CONFIG_FIELD_MARK_AS_SEEN_AFTER_PROCESSING = \
        'mark_as_seen_after_processing'
    CONFIG_FIELD_PASSWORD = 'password'
    CONFIG_FIELD_PORT = 'port'
    CONFIG_FIELD_RECIPIENT = 'recipient'
    CONFIG_FIELD_REPLAY_TO = 'replay_to'
    CONFIG_FIELD_SEARCH_FILTER = 'search_filter'
    CONFIG_FIELD_USE_SSL = 'use_ssl'
    CONFIG_FIELD_USERNAME = 'username'

    # a whitelist of headers which will not removed before resend

    HEADER_WHITELIST = {
        'subject',
        'from',
        'date',
        'content-type',
        'mime-version',
        'content-transfer-encoding',
        'x-mailer',
    }

    # here are the methods

    def __init__(self):
        super(MailSpreader, self).__init__()

    # class methode with general methods

    @classmethod
    def login_imap(cls, config, section, list_mailboxes):
        if config.getboolean(section, MailSpreader.CONFIG_FIELD_USE_SSL):
            imap_server = imaplib.IMAP4_SSL(
                host=config.get(section, MailSpreader.CONFIG_FIELD_HOST),
                port=config.get(section, MailSpreader.CONFIG_FIELD_PORT))
        else:
            imap_server = imaplib.IMAP4(
                host=config.get(section, MailSpreader.CONFIG_FIELD_HOST),
                port=config.get(section, MailSpreader.CONFIG_FIELD_PORT))

        imap_server.login(config.get(section,
                                     MailSpreader.CONFIG_FIELD_USERNAME),
                          config.get(section,
                                     MailSpreader.CONFIG_FIELD_PASSWORD))

        if list_mailboxes:
            print('Mailboxes for %(username)s@%(host)s:' % config[section])
            for mailbox in imap_server.list()[1]:
                print(mailbox.decode())
        return imap_server

    @classmethod
    def login_smtp(cls, config, section):
        if config.getboolean(section, MailSpreader.CONFIG_FIELD_USE_SSL):
            smtp_server = smtplib.SMTP_SSL(
                host=config.get(section, MailSpreader.CONFIG_FIELD_HOST),
                port=config.get(section, MailSpreader.CONFIG_FIELD_PORT))
        else:
            smtp_server = smtplib.SMTP(
                host=config.get(section, MailSpreader.CONFIG_FIELD_HOST),
                port=config.get(section, MailSpreader.CONFIG_FIELD_PORT))

        smtp_server.login(config.get(section,
                                     MailSpreader.CONFIG_FIELD_USERNAME),
                          config.get(section,
                                     MailSpreader.CONFIG_FIELD_PASSWORD))

        return smtp_server

    @classmethod
    def remove_headers(cls, headers):
        for key in headers.keys():
            if key.lower() not in MailSpreader.HEADER_WHITELIST:
                del headers[key]

    @classmethod
    def get_email_address(cls, raw_address):
        if not raw_address is None:
            match = email.utils.parseaddr(raw_address)
            if match != ('', ''):
                return match[1]
            else:
                return None
        else:
            return None

    @classmethod
    def get_domain_part(cls, address, is_raw=True):
        if is_raw:
            address = cls.get_email_address(address)

        if not address is None:
            return address.split('@')[-1]
        else:
            return None

    # preparation helper methods

    @classmethod
    def parse_arguments(cls):
        ## prepare the commandline arguments
        parser = argparse.ArgumentParser(description='',
                                         epilog="I wish you a peaceful time.")

        parser.add_argument('--log', dest='loglevel',
                            choices=["CRITICAL",
                                     "ERROR",
                                     "WARNING",
                                     "INFO",
                                     "DEBUG"],
                            default="ERROR",
                            help="choose your log level")
        parser.add_argument('-l', '--list-mailboxes', dest='list_mailboxes',
                            action='store_true')
        parser.add_argument('-d', '--dry', dest="dry_run",
                            action='store_true')
        parser.add_argument('-t', '--trace-on-error', dest='trace_exception',
                            action='store_true')
        parser.add_argument('configfile', help="the path to the config file")

        return parser.parse_args()

    def process_config(self):
        self.cfg = configparser.ConfigParser(allow_no_value=True)
        self.cfg.read(self.args.configfile)

        self.search_filter = self.cfg.get(
            MailSpreader.CONFIG_SECTION_INPUT_SERVER,
            MailSpreader.CONFIG_FIELD_SEARCH_FILTER,
            fallback=MailSpreader.CONFIG_DEFAULT_SEARCH_FILTER)

        self.mark_as_seen = self.cfg.getboolean(
            MailSpreader.CONFIG_SECTION_INPUT_SERVER,
            MailSpreader.CONFIG_FIELD_MARK_AS_SEEN_AFTER_PROCESSING,
            fallback=MailSpreader.CONFIG_DEFAULT_MARK_AS_SEEN_AFTER_PROCESSING)

        self.delete_mail = self.cfg.getboolean(
            MailSpreader.CONFIG_SECTION_INPUT_SERVER,
            MailSpreader.CONFIG_FIELD_DELETE_AFTER_PROCESSING,
            fallback=MailSpreader.CONFIG_DEFAULT_DELETE_AFTER_PROCESSING)

        self.custom_header = self.cfg.get(
            MailSpreader.CONFIG_SECTION_SEND_SERVER,
            MailSpreader.CONFIG_FIELD_CUSTOM_HEADER,
            fallback=MailSpreader.CONFIG_DEFAULT_CUSTOM_HEADER)

        self.custom_header_value = self.cfg.get(
            MailSpreader.CONFIG_SECTION_SEND_SERVER,
            MailSpreader.CONFIG_FIELD_CUSTOM_HEADER_VALUE,
            fallback=MailSpreader.CONFIG_DEFAULT_CUSTOM_HEADER_VALUE)

        self.input_mailbox = self.cfg.get(
            MailSpreader.CONFIG_SECTION_INPUT_SERVER,
            MailSpreader.CONFIG_FIELD_MAILBOX,
            fallback=MailSpreader.CONFIG_DEFAULT_MAILBOX)

        self.store_mailbox = self.cfg.get(
            MailSpreader.CONFIG_SECTION_STORE_SERVER,
            MailSpreader.CONFIG_FIELD_MAILBOX,
            fallback=MailSpreader.CONFIG_DEFAULT_MAILBOX)

        self.reply_to = self.cfg.get(
            MailSpreader.CONFIG_SECTION_MAIN,
            MailSpreader.CONFIG_FIELD_REPLAY_TO,
            fallback=MailSpreader.CONFIG_DEFAULT_REPLY_TO)

        self.check_on_return_path = self.cfg.get(
            MailSpreader.CONFIG_SECTION_MAIN,
            MailSpreader.CONFIG_FIELD_CHECK_ON_RETURN_PATH,
            fallback=MailSpreader.CONFIG_DEFAULT_CHECK_ON_RETURN_PATH)

        self.process_config_accepted_mail_addresses()
        self.load_recipient_list()

    def process_config_accepted_mail_addresses(self):
        rawvalue = self.cfg.get(
            MailSpreader.CONFIG_SECTION_MAIN,
            MailSpreader.CONFIG_FIELD_ACCEPTED_MAIL_ADDRESSES,
            fallback=MailSpreader.CONFIG_DEFAULT_ACCEPTED_MAIL_ADDRESSES)

        self.accepted_mail_addresses = []

        if not rawvalue is None:
            for match in email.utils.getaddresses([rawvalue]):
                if match != ('', ''):
                    self.accepted_mail_addresses.append(match[1])

    def setup_logging(self):
        loglevel = self.args.loglevel
        numeric_level = getattr(logging, loglevel.upper(), None)
        if not isinstance(numeric_level, int):
            raise ValueError('Invalid log level: %s' % loglevel)
        logging.basicConfig(filename=
                            self.cfg.get(MailSpreader.CONFIG_SECTION_MAIN,
                                         MailSpreader.CONFIG_FIELD_LOGFIlE),
                            level=numeric_level,
                            format='%(asctime)s [%(levelname)s]'
                            ': %(message)s')

    def load_recipient_list(self):
        raw_recipient = self.cfg.get(MailSpreader.CONFIG_SECTION_MAIN,
                                     MailSpreader.CONFIG_FIELD_RECIPIENT)
        if os.path.isfile(raw_recipient):
            with open(raw_recipient, 'r') as f:
                raw_recipient = f.read()
            f.closed

        matches = email.utils.getaddresses([raw_recipient])
        self.recipient = [m for m in matches if m != ('', '')]

    def preparations(self):
        """
        Every thing from config parsing, setup logging and load the recipient
        list is done here
        """
        self.process_config()
        self.setup_logging()

        logging.debug("Used search filter: %s" % self.search_filter)

        self.input_server = MailSpreader.login_imap(
            self.cfg, MailSpreader.CONFIG_SECTION_INPUT_SERVER,
            self.args.list_mailboxes)
        logging.debug("logged-in: input server")

        if self.input_mailbox is None:
            self.input_server.select()
            logging.debug("selected default mailbox")
        else:
            self.input_server.select(self.input_mailbox)
            logging.debug(
                "selected mailbox: %s" % self.input_mailbox)

        self.store_server = MailSpreader.login_imap(
            self.cfg, MailSpreader.CONFIG_SECTION_STORE_SERVER,
            self.args.list_mailboxes)
        logging.debug("logged-in: store server")

        self.send_server = MailSpreader.login_smtp(
            self.cfg, MailSpreader.CONFIG_SECTION_SEND_SERVER)
        logging.debug("logged-in: send server")
        logging.debug("Preparation finished")

    # processing methods

    def filter_msg(self, msg):
        """
        Returns
            * True if the message is allowed to be processed
            * False if message should be untouched.
        """

        if 'message-id' in msg:
            msg_id = msg['message_id']
        else:
            msg_id = None

        if self.accepted_mail_addresses == []:
            return True

        if self.check_on_return_path and \
                not self.get_email_address(msg['Return-Path']) \
                in self.accepted_mail_addresses:
            logging.info('msg %s rejected, return path not allowed' % msg_id)
            return False

        if not self.get_email_address(msg['From']) \
                in self.accepted_mail_addresses:
            logging.info('msg %s rejected, from address not allowed' % msg_id)
            return False

        return True

    def send_and_store_msg(self, msg, recipient, msg_org):
        del msg['Message-Id']
        msg['Message-Id'] = email.utils.make_msgid(
            domain=self.get_domain_part(msg['From']))

        del msg['To']
        msg['To'] = recipient

        if self.args.dry_run:
            print('DRY-RUN: Send message '
                  "[id: %(message-id)s   subject: %(subject)s  "
                  "form: %(from)s  to:%(to)s  "
                  "reply-to: %(reply-to)s]" % msg_org)
        else:
            self.send_server.sendmail(recipient, recipient, str(msg))

        try:
            if self.args.dry_run:
                print("DRY-RUN: Append to store server, message "
                      "[id: %(message-id)s   subject: %(subject)s  "
                      "form: %(from)s  to:%(to)s  "
                      "reply-to: %(reply-to)s]" % msg)
            else:
                self.store_server.append(self.store_mailbox, '(\\SEEN)',
                                         None, str(msg).encode())
        except:
            logging.error('Error while appending the message')
            if self.args.trace_exception:
                print(traceback.format_exc())

    def process_one_msg(self, msg_id):
        typ, data = self.input_server.fetch(msg_id, '(RFC822)')

        msg = email.message_from_string(data[0][1].decode())

        if self.args.dry_run:
            msg_org = email.message_from_string(data[0][1].decode())
        else:
            msg_org = None

        if 'message-id' in msg:
            old_msg_id = msg['message_id']
        else:
            old_msg_id = None

        if logging.getLogger().isEnabledFor(logging.DEBUG):
            if 'subject' in msg:
                _subject = msg['subject']
            else:
                _subject = None

            if 'from' in msg:
                _from = msg['from']
            else:
                _from = None

            if 'to' in msg:
                _to = msg['to']
            else:
                _to = None

            logging.debug('processing msg[%s] %s; FROM: %s; TO: %s'
                          % (old_msg_id, _subject, _from, _to))
        else:
            logging.info('processing msg with id %s' % msg_id)

        if not self.filter_msg(msg):
            if self.args.dry_run:
                print('DRY-RUN: Rejected message '
                      "[id: %(message-id)s   subject: %(subject)s  "
                      "form: %(from)s  to:%(to)s  "
                      "reply-to: %(reply-to)s]" % msg)
            return

        MailSpreader.remove_headers(msg)
        msg['reply-to'] = self.reply_to

        if not old_msg_id is None:
            msg['References'] = old_msg_id

        if self.custom_header != '':
            msg[self.custom_header] = self.custom_header_value

        for recipient in self.recipient:
            self.send_and_store_msg(msg, email.utils.formataddr(recipient),
                                    msg_org)

        if self.mark_as_seen:
            if self.args.dry_run:
                print('DRY-RUN: Mark as seen message '
                      "[id: %(message-id)s   subject: %(subject)s  "
                      "form: %(from)s  to:%(to)s  "
                      "reply-to: %(reply-to)s]" % msg_org)
            else:
                self.input_server.store(msg_id, '+FLAGS', '\\SEEN')

        if self.delete_mail:
            if self.args.dry_run:
                print('DRY-RUN: Mark as deleted message '
                      "[id: %(message-id)s   subject: %(subject)s  "
                      "form: %(from)s  to:%(to)s  "
                      "reply-to: %(reply-to)s]" % msg_org)
            else:
                self.input_server.store(msg_id, '+FLAGS', '\\Deleted')

    def process_data(self):
        try:
            typ, data = self.input_server.search(None, self.search_filter)
            for msg_id in data[0].split():
                try:
                    self.process_one_msg(msg_id)
                except:
                    logging.error('An error occured while processing msg %s'
                                  % msg_id)
                    if self.args.trace_exception:
                        print(traceback.format_exc())

            if self.delete_mail:
                if self.args.dry_run:
                    print('DRY-RUN: expunge mailbox')
                else:
                    self.input_server.expunge()
        except:
            sys.stderr.write("Something went here extremly wrong, and I don't "
                             "know why\n")
            logging.critical("Something went here extremly wrong, "
                             "and I don't know why")
            if self.args.trace_exception:
                print(traceback.format_exc())
        finally:

            self.input_server.close()
            self.input_server.logout()
            self.store_server.logout()
            self.send_server.close()

    def run(self):
        self.args = self.parse_arguments()
        self.preparations()
        logging.info("Mailspreader starts")
        self.process_data()
        logging.info("Mailspreader is done")

if __name__ == '__main__':
    spreader = MailSpreader()
    spreader.run()
