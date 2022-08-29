#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import psutil

from memory_all import Memory_all

class Os_sys(object):
    """
    Os_sys class gets basic information for the user in debug mode.
    """
    def __init__(self, my_logger_a):
        self.my_logger = my_logger_a
        self.main_pid = os.getpid()

    def current_pid(self):
        try:
            if(Memory_all.kill_print == True):
                print('[PID]\n\____The Honeypot ID is:',self.main_pid,'\n[KILL process options]\n\____SIGUSR1 (kill -USR1',self.main_pid,') -- Try clean memory dict \n\____SIGUSR2 (kill -USR2',self.main_pid,') -- Force exit process')
            self.my_logger.critical('The honeypot [pid] is ' + str(self.main_pid) + ', in case of SIGUSR1 or SIGUSR2 the tcpdump will continue to run')

        except Exception as a:
            self.my_logger.critical('force_out error, ' + str(a))

    def force_out(self):
        try:
            self.my_logger.critical('kill -USR2 Force exit process')
            p = psutil.Process(self.main_pid)
            p.terminate()  #or p.kill()

        except Exception as a:
            self.my_logger.critical('force_out error, ' + str(a))
