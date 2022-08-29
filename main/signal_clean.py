#!/usr/bin/env python
# -*- coding: utf-8 -*-

from threading import Thread, RLock

import logging
import signal
import os
import sys
import time
import datetime
import logging
import syslog
import configparser #python3

from memory_all import Memory_all
from clean_function import Clean_function
from os_sys import Os_sys
from config_file.config_honeypot import ConfigRead #read config
from syslog_._syslog import SysLogDef #syslog

#pid in os_sys class
#pid = os.getpid()

class Clean_class(object):
    """
    Clean_class receives and deals with all signals sent by the user/system (calling the clean_function when is needed).
    """
    def __init__(self, my_logger):
        self.my_logger = my_logger
        self.error_count = 0

    def send_stop_signal(self):
        try:
            #main_ lock for all procotols
            Memory_all.listening_stop = True
            self.my_logger.critical('listening_stop main_ lock for all protocols')

            #information for clean_function()
            Memory_all.dict_lock = True
            Memory_all.dict_lock_count = 1
            time.sleep(3)

        except Exception as a:
            self.my_logger.critical('send_stop_signal error,' + str(a))

    def call_clean(self):
        call_clean = Clean_function(self.my_logger)
        call_clean.run_clean()

    def run(self):
        try:
            print('Try STOP all listening ports (a message is send for all listening ports, all threads will sleep for)',Memory_all.time_signal_sleep,'seconds')
            self.send_stop_signal()
            print('Now Dict will be call [Default Try is ',Memory_all.default_try,'], then the system will stop (The system will wait the function wakeup, the Default time is ',60*Memory_all.time_clean_ignore,' seconds)')
            while (Memory_all.dict_lock == True):
                time.sleep(60)
                print('[DICT_CLEAN LOCK] ON [Time wating is',self.error_count*60,']')
                self.error_count+=1

            print('[DICT_CLEAN LOCK] OFF ... Try end Honeypot')

        except Exception as a:
            self.my_logger.error('[SIGUSR1 Exception log in log_error.txt]' + str(a))
            #print('[SIGUSR1 Exception log in log_error.txt]',a)


class Force_exit(object):
    """
    Force_exit class is responsible for a force shutdown of the system without precaution with the information that is not in the database.
    """
    def __init__(self, my_logger):
        self.my_logger = my_logger

    def run(self):
        try:
            self.my_logger.critical('Force_exit ')
            sys.exit(1)

        except Exception as a:
            self.my_logger.critical('SIGUSR2 Exception log ' + str(a))

        finally:
            print('[WARNING] TCPDUMP WILL CONTINUE TO LISTENING, FOR SAFETY MEASURES')

#signalkill clean all dict before close the program
def receive_signal_one(signum, stack):
    try:
        #call and print all keys in memory dict
        print('[SIGNAL USR1] Received:', signum)

        #syslog read information
        get_syslog = ConfigRead()
        file_syslog = get_syslog.red_syslog()
        #syslog get logger
        syslog_run = SysLogDef(file_syslog)
        my_logger = syslog_run.run()

        #call function clean here
        try_clean = Clean_class(my_logger)
        try_clean.run()

    except Exception as a:
        print('[Signal USR1] ERROR' + str(a))

    finally:
        #print('[Signal USR1] Bye')
        force = Force_exit(my_logger)
        force.run()

def receive_signal_two(signum, stack):
    try:
        print('[Signal USR2] Received:', signum)
        #force = Force_exit()
        #force.run()

        #syslog read information
        get_syslog = ConfigRead()
        file_syslog = get_syslog.red_syslog()
        #syslog get logger
        syslog_run = SysLogDef(file_syslog)
        my_logger = syslog_run.run()

        force = Os_sys(my_logger)
        force.force_out()

    except Exception as a:
        print('[Signal USR2] ERROR' + str(a))

    finally:
        print('[Signal USR2]')

signal.signal(signal.SIGUSR1, receive_signal_one)
signal.signal(signal.SIGUSR2, receive_signal_two)
