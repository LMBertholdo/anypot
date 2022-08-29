#!/usr/bin/env python
# -*- coding: utf-8 -*-

from threading import Thread, RLock

from memory_all import Memory_all

import argparse
import time
import threading

from steam_.steam import Steam
from steam_.memory import Memory
from steam_.db import DB

class Run_ports(object):
    """
    Main function of steam honeypot, start all threads here
    """

    def __init__(self, bind_address, my_logger):
        self.bind_address = bind_address
        #self.bind_port = 27000 #inicial
        self.list_udp = [27015]
        #self.list_udp = [4380, 20800, 27005, 27015, 27030, 27036]
        #self.list_tcp = [27015,27030]
        self.list_tcp = [27015]
        self.n_threads = len(self.list_tcp) + len(self.list_udp)
        self.my_logger = my_logger

    def _supe_thread(self):
        if(Memory.flag_print == True):
            print('[*SUPER_THREAD]')
        try:
            #time.sleep(60* (Memory.time_thread_clean_dict))
            if(Memory.flag_print == True):
                print('[*THREAD] Clean dict')

            db_name = 'database/dnstor_statistics_steam_games.sqlite'#database name

            _background_dict_ = DB(db_name, self.my_logger) #call database class
            _background_dict_.run_db()#run database class

        except KeyboardInterrupt:
            print('[*THREAD] _supe_thread Stop [steam]')
            self.my_logger.error('[*THREAD] _supe_thread Stop [steam] KeyboardInterrupt')

        except Exception as e:
            print('[steam _supe_thread function]',e)
            self.my_logger.critical('[steam _supe_thread function]' + str(e))

    def worker(self):
        if(Memory.flag_print == True):
            print('[Worker] start')

        time.sleep(0.5)
        if(Memory_all.main_all_prints == True):
            print('[Games] listening [Steam, RCON, SRCDS and Call Of Duty] \n| list of ports that are been listening: \n| UDP:',self.list_udp,'\n| TCP:', self.list_tcp, '\n| Number total of Threads [Games]:', self.n_threads)
        try:
            #First TCP
            for i in range(len(self.list_tcp)):
                server = Steam(self.bind_address, self.list_tcp[i],'TCP', self.my_logger)
                server.run()

            #Second UDP
            for i in range(len(self.list_udp)):
                server = Steam(self.bind_address, self.list_udp[i],'UDP', self.my_logger)
                server.run()

        except Exception as e:
            print('[steam worker function]',e)
            self.my_logger.critical('[steam worker function]' + str(e))

        finally:
            time.sleep(0.5)

            if(Memory.flag_print == True):
                print('[Worker] done')
