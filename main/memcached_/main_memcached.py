#!/usr/bin/env python
# -*- coding: utf-8 -*-

from threading import Thread, RLock
from datetime import datetime

from memcached_.memory import Memory
from memcached_.db import DB_DNSTor
from memcached_.memcached import Memcached
from memcached_.log_commands import Other_msg #,Log_commands
from memcached_.ignore import Ig, Modify_ip, Hour_verify, Creat_dict_ig, Ignore_dict

from memory_all import Memory_all

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

class Proxy_memcached(object):
    """
    Main Struct to memcached honeypot
    """
    def __init__(self,memcached_bind_address,memcached_bind_port,memcached_bind_ip_server,memcached_bind_port_server, my_logger):

        #honeypot socket
        self.ip = memcached_bind_address#'127.0.0.1'
        self.port = memcached_bind_port#11000

        #server socket
        self.ip_server = memcached_bind_ip_server#'127.0.0.1'
        self.port_server = memcached_bind_port_server#11211

        self.my_logger = my_logger

    def bind_faster_then__init__(self):
        try:
            #UDP honeypot
            self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.s.bind((self.ip,self.port))

            self.sock_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock_server.connect((self.ip_server,self.port_server))

        except Exception as e:
            print('[memcached bind_faster_then__init__ function]',e)
            self.my_logger.critical('[memcached bind_faster_then__init__ function]' + str(e))

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
                print("[memcached] This index does not exist!")
                self.my_logger.critical('[memcached UpdateMemory function IndexError]')
            except KeyError:
                print("[memcached] This key is not in the dictionary!")
                self.my_logger.critical('[memcached UpdateMemory function KeyError]')
            except TypeError:
                print("[memcached] Object does not support (tuple problem)")
                self.my_logger.critical('[memcached UpdateMemory function TypeError]')
            except Exception as e:
                print('[memcached UpdateMemory function]',e)
                self.my_logger.critical('[memcached UpdateMemory function]' + str(e))

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

    #call server function
    def call_server(self, package_info,address):
        """
        This function will call Log_commands that respond True or False. True if the question recive is 'stats' and False for other types of messages
        """

        try:
            worker_verify = Other_msg(package_info,address)
            value , result = worker_verify.run()

            if(Memory.flag_print == True):
                print('value:',value,'result:', result)

            if(value == True):
                new_package_info = bytes(("stats\n").encode('UTF-8'))
                #print(new_package_info)
                worker_server = Memcached(self.s, self.sock_server,new_package_info , address, self.my_logger)
                worker_server.run_worker()
            else:
                self.s.sendto(bytes(result.encode('UTF-8')),address)

        except Exception as e:
            print('[memcached call_server function]',e)
            self.my_logger.critical('[memcached call_server function]' + str(e))

    def _port_listening(self):
        if(Memory_all.main_all_prints == True):
            print('[*Loop] [Memcached] [UDP], address {} and port {} '.format(self.ip,self.port))
        self.bind_faster_then__init__()

        while True:
            try:
                data, addr = self.s.recvfrom(1024)

                #signal flag stop
                if(Memory_all.dict_lock == True):
                    time.sleep(Memory_all.time_signal_sleep)

                if(Memory.flag_print == True):
                    print(data,addr)

                    print("[Info] Client send : ", data.strip() )

                not_tuple_addr = addr[0] #just ip (same port ...)
                print('[memcached]',not_tuple_addr)

                if ((self.SearchMemory(not_tuple_addr)) == None ):
                    if(Memory.flag_print == True):
                        print('[*MEMORY] Not ip ')

                    #first add memory
                    self.AddIpMemory(not_tuple_addr, 1, datetime.datetime.now(), datetime.datetime.now(), str(data))

                    #verify ignore dictionay
                    worker = Ig(not_tuple_addr)
                    b = worker.run()

                    if(b == True):
                        #in memory Ig
                        print('[Chargen] Ignore dict [add]', not_tuple_addr)
                    else:
                        #server class already send package UDP to client
                        self.call_server(data,addr)

                else:
                    if(Memory.flag_print == True):
                        print ('[*MEMORY] True')
                    self.UpdateMemory(not_tuple_addr)

                    if(self._i_must_answer(not_tuple_addr) == True):
                        self.call_server(data,addr)

                #count to use in _control_clean_dict
                Memory._count_use+=1

                if(Memory._count_use > 1000000000):
                    if(Memory.flag_print == True):
                        print('[*MEMORY] _count_use = 1')
                    self.my_logger.warning('[memcached _port_listening _count_use]' + str(Memory._count_use))
                    Memory._count_use = 1
                    print(Memory._count_use)


            except KeyboardInterrupt:
                self.s.close()
                self.sock_server.close()
                self.my_logger.error('[memcached KeyboardInterrupt]')

            except Exception as e:
                print('[memcached _port_listening function]',e)
                print('[memcached _port_listening', datetime.datetime.now(), data, addr)
                self.my_logger.critical('[memcached _port_listening function]' + str(e) + ' DATA: ' + str(data) + ' ADDRESS: ' + str(addr))

            finally:
                if(Memory.flag_print == True):
                    print("[Working]")

    def _supe_thread(self):
        try:
            #while True:
                #time.sleep(60* (Memory.time_thread_clean_dict))
            if(Memory.flag_print == True):
                print('[*THREAD] Clean dict')
            #print(Memory.dicio)
            #define DB name
            db_name = './database/dnstor_statistics_memcached.sqlite'

            _background_dict_ = DB_DNSTor(db_name, self.ip, self.port, self.my_logger)

            _background_dict_._run_db()

        except KeyboardInterrupt:
            print('[*THREAD] _supe_thread Stop [memcached]')
            self.my_logger.error('[*THREAD] _supe_thread Stop [memcached] KeyboardInterrupt')

        except Exception as e:
            print('[memcached _supe_thread function]',e)
            self.my_logger.critical('[memcached _supe_thread function]' + str(e))

    def run(self):
        try:
            #Starts the server
            if(Memory.flag_print == True):
                print('[*LOADING memcached]')
            time.sleep(1)

            t2 = Thread(target=self._port_listening)

            t2.start()

        except KeyboardInterrupt:
            print('[*RUN] Stop working? Thread problem [memcached]')
            self.my_logger.error('[memcached Run function KeyboardInterrupt]')

        except Exception as e:
            print('[memcached run function]',e)
            self.my_logger.critical('[memcached Run function]' + str(e))
