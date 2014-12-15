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

    def __init__(self):
        super(MailSpreader, self).__init__()

    @classmethod
    def login_imap(cls, config, section):
        if config.getboolean(section, 'use_ssl'):
            imap_server = imaplib.IMAP4_SSL(
                host=config.get(section, 'host'),
                port=config.get(section, 'port'))
        else:
            imap_server = imaplib.IMAP4(
                host=config.get(section, 'host'),
                port=config.get(section, 'port'))

        imap_server.login(config.get(section, 'username'),
                          config.get(section, 'password'))

        return imap_server

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
        self.cfg = configparser.ConfigParser()
        self.cfg.read(self.args.configfile)
        print(self.cfg.sections())
        for section in self.cfg.sections():
            print('%s\n---------' % section)
            for option in self.cfg.options(section):
                print("'%s':'%s'" % (option, self.cfg.get(section, option)))

    def setup_logging(self):
        loglevel = self.args.loglevel
        numeric_level = getattr(logging, loglevel.upper(), None)
        if not isinstance(numeric_level, int):
            raise ValueError('Invalid log level: %s' % loglevel)
        logging.basicConfig(filename=self.cfg.get('MAIN', 'logfile'),
                            level=numeric_level,
                            format='%(asctime)s [%(levelname)s]'
                            ': %(message)s')

    def login_input_server(self):
        if self.cfg.getboolean('INPUT-SERVER', 'use_ssl'):
            self.input_server = imaplib.IMAP4_SSL(
                host=self.cfg.get('INPUT-SERVER', 'host'),
                port=self.cfg.get('INPUT-SERVER', 'port'))
        else:
            self.input_server = imaplib.IMAP4(
                host=self.cfg.get('INPUT-SERVER', 'host'),
                port=self.cfg.get('INPUT-SERVER', 'port'))

        self.input_server.login(self.cfg.get('INPUT-SERVER', 'username'),
                                self.cfg.get('INPUT-SERVER', 'password'))

    def login_store_server(self):
        if self.cfg.getboolean('INPUT-SERVER', 'use_ssl'):
            self.input_server = imaplib.IMAP4_SSL(
                host=self.cfg.get('INPUT-SERVER', 'host'),
                port=self.cfg.get('INPUT-SERVER', 'port'))
        else:
            self.input_server = imaplib.IMAP4(
                host=self.cfg.get('INPUT-SERVER', 'host'),
                port=self.cfg.get('INPUT-SERVER', 'port'))

        self.input_server.login(self.cfg.get('INPUT-SERVER', 'username'),
                                self.cfg.get('INPUT-SERVER', 'password'))

    def preparations(self):
        self.parse_arguments()
        self.process_config()
        self.setup_logging()
        logging.debug("Preparation finished")

        self.input_server = MailSpreader.login_imap(self.cfg, 'INPUT-SERVER')
        logging.debug("logged-in: input server")

        self.store_server = MailSpreader.login_imap(self.cfg, 'STORE-SERVER')
        logging.debug("logged-in: store server")

    def process_data(self):

        O = smtplib.SMTP('wp292.webpack.hosteurope.de')
        O.login("wp1134078-shtest2", "posttest2")

        liste = self.store_server.list()

        print(liste[1])

        newliste = []
        for x in liste[1]:
            newliste.append(x.decode())

        print(newliste)

        try:
            self.input_server.select()
            print(self.store_server.select('"Sent\ Messages"'))

            print('I am here')

            typ, data = self.input_server.search(None, 'ALL')
            for num in data[0].split():
                typ, data = self.input_server.fetch(num, '(RFC822)')
                # print("NUM:", num)
                # print("DATA:", data)
                # print("type:", typ)
                # print('Message %s\n%s\n' % (num, data[0][1]))
                # N.append(None, None, None, data[0][1])
                msg1 = email.message_from_string(data[0][1].decode('utf-8'))

                print(msg1.keys())

                for key in msg1.keys():
                    print(key, key.lower())
                    if key.lower() not in {'subject', 'from', 'date',
                                           'content-type', 'mime-version',
                                           'content-transfer-encoding',
                                           'message-id', 'x-mailer'}:
                        del msg1[key]
                msg1['To'] = 'mail@sh-dev.de'

                msg1['X-SHdever'] = 'mail@sh-dev.de'
                print(msg1.keys())

                O.sendmail("mail@sh-dev.de", "mail@sh-dev.de", str(msg1))

                self.store_server.append('"Sent\ Messages"',
                                         None, None,
                                         str(msg1).encode())
                self.input_server.store(num, '+FLAGS', '\\Deleted')

                print('--------------------')
            self.input_server.expunge()
        except:
            sys.stderr.write("Something went here extremly wrong, and I don't "
                             "know why\n")
            self.logging.critical("Something went here extremly wrong, "
                                  "and I don't know why")
        finally:
            self.input_server.close()
            self.input_server.logout()
            self.store_server.close()
            self.store_server.logout()
            O.close()

if __name__ == '__main__':
    spreader = MailSpreader()
    spreader.main()
