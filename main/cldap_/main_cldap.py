#!/usr/bin/env python
# -*- coding: utf-8 -*-

from threading import Thread, RLock
from datetime import datetime

# from cldap_.cldap import run_call
from cldap_.cldap import *
from cldap_.db import DB_DNSTor
from cldap_.memory import Memory
from cldap_.ignore import Ig, Modify_ip, Hour_verify, Creat_dict_ig, Ignore_dict

from memory_all import Memory_all

from syslog_._syslog import SysLogDef #syslog

import argparse
import socket
import sqlite3
import threading
import datetime
import time
import select
import subprocess

import csv
import sys

class Proxy_cldap(object):
    """
    Main class of cldap honeypot
    """

    def __init__(self, bind_address, bind_port, my_logger):
        self.port = bind_port
        self.ip = bind_address
        self.my_logger = my_logger

    #add element in memory
    def AddIpMemory(self, ip , count, tempoInicio, tempoFinal, payload):
            Memory.dicio[ip] = (count, tempoInicio, tempoFinal, payload)

    #search element in memory
    def SearchMemory(self,ip):
        if ip in Memory.dicio:
            if(Memory.flag_print == True):
                print(ip, Memory.dicio[ip])
            return False

    #update value in memory(remove ....)
    def UpdateMemory(self,ip):
        if ip in Memory.dicio:
            try:
                #temp value
                ip = ip
                count = Memory.dicio[ip][0]
                tempoInicio = Memory.dicio[ip][1]
                tempoFinal = datetime.datetime.now()
                payload = str(Memory.dicio[ip][3])

                #remove key for update count value
                del Memory.dicio[ip]

                #add count
                count += 1

                #ADD key again
                self.AddIpMemory(ip, count, tempoInicio, tempoFinal, payload)

            except IndexError:
                print("[cldap] This index does not exist!")
                self.my_logger.critical('[cldap UpdateMemory function IndexError]')
            except KeyError:
                print("[cldap] This key is not in the dictionary!")
                self.my_logger.critical('[cldap UpdateMemory function KeyError]')
            except TypeError:
                print("[cldap] Object does not support (tuple problem)")
                self.my_logger.critical('[cldap UpdateMemory function TypeError]')

    def send_cldap(self, data):
        try:
            value = run_call(data)

            if(Memory.flag_print == True):
                print('worker 2')

            return value
        except Exception as a:
            print('[cldap return msg]', a)
            self.my_logger.critical('[cldap send_cldap function]' + str(a))

    #verifica o linite de respostas
    def _i_must_answer(self,ip):
        if(Memory.dicio[ip][0]>Memory.count_max):
            return False
        elif(Memory.dicio[ip][0]>(Memory.count_max - 1)):
            add_ignore_ip = Modify_ip(ip)
            add_ignore_ip.AddIpMemory()
        else:
            #verify ignore dictionay
            worker = Ig(ip)
            b = worker.run()

            if(b == True):
                return False
            else:
                return True

    def _port_listening(self):
        if(Memory_all.main_all_prints == True):
            print('[*Loop] [cldap] [UDP], address {} and port {}'.format(self.ip,self.port))

        self.socks = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socks.bind((self.ip,self.port))

        while True:
            try:
                data, addr = self.socks.recvfrom(8192)

                #signal flag stop
                if(Memory_all.dict_lock == True):
                    time.sleep(Memory_all.time_signal_sleep)

                if(Memory.flag_print == True):
                    print (addr)

                not_tuple_addr = addr[0] #just ip (same port ...)
                print('[cldap]',not_tuple_addr)

                if ((self.SearchMemory(not_tuple_addr)) == None ):
                    if(Memory.flag_print == True):
                        print('[*MEMORY] Not ip ')

                    #first add memory
                    self.AddIpMemory(not_tuple_addr, 1, datetime.datetime.now(), datetime.datetime.now(), str(data))

                    #verify ignore dictionay
                    worker = Ig(not_tuple_addr)
                    b = worker.run()

                    if(b == True):
                        print('[cldap] Ignore dict [add]', not_tuple_addr)
                    else:
                        try:
                            qt = (self.send_cldap(data))
                            if(Memory.flag_print == True):
                                print(qt)

                            self.socks.sendto(bytes(qt),addr)

                        except Exception as e:
                            print('Error cldap Lookup 1', e)
                            self.my_logger.critical('[Error cldap in Lookup 1]' + str(e))
                            continue

                else:
                    if(Memory.flag_print == True):
                        print ('[*MEMORY] True')
                    self.UpdateMemory(not_tuple_addr)

                    if(self._i_must_answer(not_tuple_addr) == True):
                        try:
                            qt = (self.send_cldap(data))
                            if(Memory.flag_print == True):
                                print(qt)

                            #UDP
                            self.socks.sendto(bytes(qt),addr)

                        except Exception as e:
                            print('Error cldap Lookup 2', e)
                            self.my_logger.critical('[Error cldap in Lookup 2]' + str(e))
                            continue

                #count to use in _control_clean_dict
                Memory._count_use+=1

                if(Memory._count_use > 1000000000):
                    if(Memory.flag_print == True):
                        print('[*MEMORY] _count_use = 1')
                    self.my_logger.warning('[cldap _port_listening _count_use]' + str(Memory._count_use))
                    Memory._count_use = 1
                    print(Memory._count_use)


            except KeyboardInterrupt:
                #UDP
                self.socks.close()
                self.my_logger.error('[cldap KeyboardInterrupt]')
                break

            except Exception as e:
                # [Errno 22] Invalid argument
                print('[cldap _port_listening function]',e, data, addr)
                self.my_logger.critical('[cldap _port_listening function]' + str(e) + ' DATA: ' + str(data) + ' ADDRESS: ' + str(addr))
                continue

            finally:
                pass

    def _supe_thread(self):
        try:
            #time.sleep(60* (Memory.time_thread_clean_dict))
            time.sleep(1)
            if(Memory.flag_print == True):
                print('[*THREAD] Clean dict')
            #print(Memory.dicio)

            #define DB name
            db_name = 'database/dnstor_statistics_cldap.sqlite'

            _background_dict_ = DB_DNSTor(db_name, self.ip, self.port, self.my_logger)
            _background_dict_._run_db()

        except KeyboardInterrupt:
            print('[*THREAD] _supe_thread Stop [cldap]')
            self.my_logger.error('[*THREAD] _supe_thread Stop [cldap] KeyboardInterrupt')

        except Exception as e:
            print('[cldap _supe_thread function]',e)
            self.my_logger.critical('[cldap _supe_thread function]' + str(e))

    def run(self):
        try:
            if(Memory.flag_print == True):
                print('[*LOADING cldap]')
            time.sleep(1)
            t2 = Thread(target=self._port_listening)
            t2.start()

        except KeyboardInterrupt:
            print('[*RUN] Stop working? Thread problem [cldap]')
            self.my_logger.error('[cldap Run function KeyboardInterrupt]')

        except Exception as e:
            print('[cldap Run function]',e)
            self.my_logger.critical('[cldap Run function]' + str(e))
