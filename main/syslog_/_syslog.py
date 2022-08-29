#!/usr/bin/env python
# -*- coding: utf-8 -*-

import syslog
import logging
import configparser #python3
import io
import sys
import datetime

class SysLogDef:
    """
    SysLogDef defines the syslog level in the honeypot.
    """

    def __init__(self, level):
        self.level = level
        self.fileName = str('./syslog_/log/logname.log.' + str(datetime.datetime.now()))

    def run(self):
        #
        try:
            my_logger = logging.getLogger()

            #open the config file again
            logging.basicConfig(filename=str(self.fileName),format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s', datefmt='%Y-%m-%d %H:%M:%S -- ',filemode='a')

            #very input, level syslog
            if(self.level.upper() in 'INFO'):
                my_logger.setLevel(logging.INFO)
            elif(self.level.upper() in 'DEBUG'):
                my_logger.setLevel(logging.DEBUG)
            elif(self.level.upper() in 'WARNING'):
                my_logger.setLevel(logging.WARNING)
            elif(self.level.upper() in 'ERROR'):
                my_logger.setLevel(logging.ERROR)
            elif(self.level.upper() in 'CRITICAL'):
                my_logger.setLevel(logging.CRITICAL)
            else:
                print('[ERROR syslog level]')
                my_logger.setLevel(logging.ERROR)
                my_logger.error('Syslog invalid option in file config_file.ini')
                sys.exit(1)

            my_logger.debug('Syslog class run function')

            return my_logger

        except Exception as a:
            my_logger.critical('syslog class error' + str(a))
