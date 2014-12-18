#!/usr/bin/env python3

import email
import imaplib
import smtplib
import configparser
import argparse
import logging
import sys


class MailSpreader(object):
    """The class is basic script for sending a mails to \
    multiply destinantions"""

    CONFIG_SECTION_INPUT_SERVER = "INPUT-SERVER"
    CONFIG_SECTION_MAIN = "MAIN"
    CONFIG_SECTION_SEND_SERVER = "SEND-SERVER"
    CONFIG_SECTION_STORE_SERVER = "STORE-SERVER"

    CONFIG_DEFAULT_DELETE_AFTER_PROCESSING = False
    CONFIG_DEFAULT_MARK_AS_SEEN_AFTER_PROCESSING = True
    CONFIG_DEFAULT_SEARCH_FILTER = 'NEW'

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
    CONFIG_FIELD_SEARCH_FILTER = 'search_filter'
    CONFIG_FIELD_USE_SSL = 'use_ssl'
    CONFIG_FIELD_USERNAME = 'username'

    HEADER_EXCLUDES = {'subject', 'from', 'date', 'content-type',
                       'mime-version', 'content-transfer-encoding',
                       'message-id', 'x-mailer'}

    def __init__(self):
        super(MailSpreader, self).__init__()

    @classmethod
    def login_imap(cls, config, section):
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
            if key.lower() not in MailSpreader.HEADER_EXCLUDES:
                del headers[key]

    def main(self):
        self.preparations()
        self.process_data()

    def parse_arguments(self):
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

        parser.add_argument('configfile', help="the path to the config file")

        self.args = parser.parse_args()

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
            fallback="")

        self.custom_header_value = self.cfg.get(
            MailSpreader.CONFIG_SECTION_SEND_SERVER,
            MailSpreader.CONFIG_FIELD_CUSTOM_HEADER_VALUE,
            fallback="")

        self.recipient = self.cfg.get(MailSpreader.CONFIG_SECTION_SEND_SERVER,
                                      MailSpreader.CONFIG_FIELD_RECIPIENT)

        self.input_mailbox = self.cfg.get(
            MailSpreader.CONFIG_SECTION_INPUT_SERVER,
            MailSpreader.CONFIG_FIELD_MAILBOX, fallback=None)

        self.store_mailbox = self.cfg.get(
            MailSpreader.CONFIG_SECTION_STORE_SERVER,
            MailSpreader.CONFIG_FIELD_MAILBOX, fallback=None)

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

    def preparations(self):
        self.parse_arguments()
        self.process_config()
        self.setup_logging()
        logging.info("Mailspreader starts")

        logging.debug("Used search filter: %s" % self.search_filter)

        self.input_server = MailSpreader.login_imap(
            self.cfg, MailSpreader.CONFIG_SECTION_INPUT_SERVER)
        logging.debug("logged-in: input server")

        if self.input_mailbox is None:
            print(self.input_server.select())
            logging.debug("selected default mailbox")
        else:
            self.input_server.select(self.input_mailbox)
            logging.debug(
                "selected mailbox: %s" % self.input_mailbox)

        self.store_server = MailSpreader.login_imap(
            self.cfg, MailSpreader.CONFIG_SECTION_STORE_SERVER)
        logging.debug("logged-in: store server")

        self.send_server = MailSpreader.login_smtp(
            self.cfg, MailSpreader.CONFIG_SECTION_SEND_SERVER)
        logging.debug("logged-in: send server")
        logging.debug("Preparation finished")

    def process_one_msg(self, msg_id):
        typ, data = self.input_server.fetch(msg_id, '(RFC822)')
        msg = email.message_from_string(data[0][1].decode())
        MailSpreader.remove_headers(msg)
        msg['To'] = self.recipient

        if self.custom_header != '':
            msg[self.custom_header] = self.custom_header_value

        self.send_server.sendmail(self.recipient,
                                  self.recipient, str(msg))

        self.store_server.append(self.store_mailbox, None, None,
                                 str(msg).encode())

        if self.mark_as_seen:
            self.input_server.store(msg_id, '+FLAGS', '\\SEEN')

        if self.delete_mail:
            self.input_server.store(msg_id, '+FLAGS', '\\Deleted')

    def process_data(self):

        try:
            typ, data = self.input_server.search(None, self.search_filter)

            for msg_id in data[0].split():

                try:
                    self.process_one_msg(msg_id)
                finally:
                    pass

            if self.delete_mail:
                self.input_server.expunge()
        except:
            sys.stderr.write("Something went here extremly wrong, and I don't "
                             "know why\n")
            self.logging.critical("Something went here extremly wrong, "
                                  "and I don't know why")
        finally:

            self.input_server.close()
            self.input_server.logout()
            self.store_server.logout()
            self.send_server.close()

if __name__ == '__main__':
    spreader = MailSpreader()
    spreader.main()
