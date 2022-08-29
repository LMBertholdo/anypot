#!/usr/bin/env python
# -*- coding: utf-8 -*-

from threading import Thread, RLock
from datetime import datetime

from ntp_.ntp import NTP
from ntp_.db import DB_DNSTor
from ntp_.memory import Memory
from ntp_.ignore import Ig, Modify_ip, Hour_verify, Creat_dict_ig, Ignore_dict
from ntp_.signature import Signature

from memory_all import Memory_all

import argparse
import socket
import sqlite3
import threading
import datetime
import subprocess
import time

class Proxy_ntp(object):
    """
    Main class of ntp honeypot
    """

    def __init__(self, bind_address, bind_port, my_logger):
        self.port = bind_port
        self.ip = bind_address
        self.my_logger = my_logger

        self.build_signature = Signature(self.my_logger)
        self.build_signature.build()

##memory dict

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
                print("[ntp] This index does not exist!")
                self.my_logger.critical('[ntp UpdateMemory function IndexError]')
            except KeyError:
                print("[ntp] This key is not in the dictionary!")
                self.my_logger.critical('[ntp UpdateMemory function KeyError]')
            except TypeError:
                print("[ntp] Object does not support (tuple problem)")
                self.my_logger.critical('[ntp UpdateMemory function TypeError]')
            except Exception as e:
                print('[ntp UpdateMemory function]',e)
                self.my_logger.critical('[ntp UpdateMemory function]' + str(e))

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

    def find_ntp_resp(self, data, addr, socket_t):
        try:
            self.build_signature.resolve_question(data, addr, socket_t)

        except Exception as a:
            print('[ntp find_ntp_resp]', a)
            self.my_logger.critical('[ntp find_ntp_resp function]' + str(a))

    def _port_listening(self):

        self.socks = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socks.bind((self.ip,self.port))

        if(Memory_all.main_all_prints == True):
            print('[*Loop] [NTP] [UDP], address {} and port {}'.format(self.ip,self.port))

        while True:
            try:

                data, addr = self.socks.recvfrom(8192)

                #signal flag stop
                if(Memory_all.dict_lock == True):
                    time.sleep(Memory_all.time_signal_sleep)

                if(Memory.flag_print == True):
                    print (addr)

                not_tuple_addr = addr[0] #just ip (same port ...)
                print('[ntp]',not_tuple_addr)

                if ((self.SearchMemory(not_tuple_addr)) == None ):
                    if(Memory.flag_print == True):
                        print('[*MEMORY] Not ip ')

                    #first add memory
                    self.AddIpMemory(not_tuple_addr, 1, datetime.datetime.now(), datetime.datetime.now(), str(data))

                    #verify ignore dictionay
                    worker = Ig(not_tuple_addr)
                    b = worker.run()

                    if(b == True):
                        print('[ntp] Ignore dict [add]', not_tuple_addr)
                    else:
                        self.find_ntp_resp(data, addr, self.socks)

                else:
                    if(Memory.flag_print == True):
                        print ('[*MEMORY] True')
                    self.UpdateMemory(not_tuple_addr)

                    if(self._i_must_answer(not_tuple_addr) == True):
                        self.find_ntp_resp(data, addr, self.socks)

                #count to use in _control_clean_dict
                Memory._count_use+=1

                if(Memory._count_use > 1000000000):
                    if(Memory.flag_print == True):
                        print('[*MEMORY] _count_use = 1')
                    self.my_logger.warning('[ntp _port_listening _count_use]' + str(Memory._count_use))
                    Memory._count_use = 1
                    print(Memory._count_use)

            except KeyboardInterrupt:
                self.socks.close()
                self.my_logger.error('[ntp KeyboardInterrupt]')
                break

            except Exception as e:
                print('[ntp _port_listening function]',e)
                self.my_logger.critical('[ntp _port_listening function]' + str(e) + ' DATA: ' + str(data) + ' ADDRESS: ' + str(addr))

    def _supe_thread(self):
        try:
            #time.sleep(60* (Memory.time_thread_clean_dict))
            time.sleep(1)
            if(Memory.flag_print == True):
                print('[*THREAD] Clean dict')
            #print(Memory.dicio)

            #define DB name
            db_name = 'database/dnstor_statistics_ntp.sqlite'

            _background_dict_ = DB_DNSTor(db_name, self.ip, self.port, self.my_logger)
            _background_dict_._run_db()

        except KeyboardInterrupt:
            print('[*THREAD] _supe_thread Stop [ntp]')
            self.my_logger.error('[*THREAD] _supe_thread Stop [ntp] KeyboardInterrupt')

        except Exception as e:
            print('[ntp _supe_thread function]',e)
            self.my_logger.critical('[ntp _supe_thread function]' + str(e))

    def run(self):
        try:
            if(Memory.flag_print == True):
                print('[*LOADING NTP]')
            time.sleep(1)
            t2 = Thread(target=self._port_listening)
            t2.start()

        except KeyboardInterrupt:
            print('[*RUN] Stop working? Thread problem [ntp]')
            self.my_logger.error('[ntp Run function KeyboardInterrupt]')

        except Exception as e:
            print('[ntp Run function]',e)
            self.my_logger.critical('[ntp Run function]' + str(e))
