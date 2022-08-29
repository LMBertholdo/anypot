#!/usr/bin/env python
# -*- coding: utf-8 -*-

from threading import Thread, RLock
from datetime import datetime

# from coap_.coap2 import *
# from coap_.coap import CoAP
from coap_.db import DB_DNSTor
from coap_.memory import Memory
from coap_.ignore import Ig, Modify_ip, Hour_verify, Creat_dict_ig, Ignore_dict

from memory_all import Memory_all

from syslog_._syslog import SysLogDef #syslog

from aiocoap import *
import asyncio

from tornado.platform.asyncio import AnyThreadEventLoopPolicy

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

@asyncio.coroutine
def main(request_atk):
    try:
        protocol = yield from Context.create_client_context()
        # request = Message(code=GET, mid=request_atk.mid, token=request_atk.token, mtype=request_atk.mtype)
        request = Message(code=GET)
        # request.set_request_uri('coap://127.0.0.1/.well-known/core')
        request.set_request_uri('coap://localhost/.well-know/core')
    except Exception as a:
        print('[coap main protocol message error]', a)

    try:
        # response = yield from protocol.request(request).response
        rrr = yield from protocol.request(request).response
    except Exception as e:
        print('[coap main request_atk] Failed to fetch resource in CoAP server:', e)
    else:
        # print('Result: %s\n%r'%(rrr.code, rrr.payload))
        return rrr

class Proxy_coap(object):
    """
    Main class of coap honeypot
    """

    def __init__(self, bind_address, bind_port, my_logger):
        self.port = bind_port
        self.ip = bind_address
        self.my_logger = my_logger

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
                print("[coap] This index does not exist!")
                self.my_logger.critical('[coap UpdateMemory function IndexError]')
            except KeyError:
                print("[coap] This key is not in the dictionary!")
                self.my_logger.critical('[coap UpdateMemory function KeyError]')
            except TypeError:
                print("[coap] Object does not support (tuple problem)")
                self.my_logger.critical('[coap UpdateMemory function TypeError]')
            except Exception as e:
                print('[coap UpdateMemory function]',e)
                self.my_logger.critical('[coap UpdateMemory function]' + str(e))

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

    def sendrq(self, data, addr):
        try:

            asyncio.set_event_loop_policy(AnyThreadEventLoopPolicy())
        except Exception as e:
            print('[coap sendrq set_event_loop_policy]',e)
            self.my_logger.critical('[coap sendrq set_event_loop_policy]' + str(e))
            return 0

        try:
            rr = asyncio.get_event_loop().run_until_complete(main(data))
            # print(rr.code, rr.payload, rr.mid, rr.token)
        except Exception as e:
            print('[coap sendrq get_event_loop]',e)
            self.my_logger.critical('[coap sendrq get_event_loop]' + str(e))
            return 0

        try:
            # bytes to int, and write header
            rr.mid = int.from_bytes(data[1:3], byteorder='big', signed=True)
        except Exception as e:
            print('[coap sendrq mid]',e)
            self.my_logger.critical('[coap sendrq mid]' + str(e))
            return 0

        try:
            rr.token = data[4:8]
        except Exception as e:
            print('[coap sendrq token]',e)
            self.my_logger.critical('[coap sendrq token]' + str(e))
            return 0

        try:
            self.socks.sendto(rr.encode(), addr)
        except Exception as e:
            print('[coap sendrq function]',e)
            print('[coap sendrq', datetime.datetime.now(), data, addr)
            self.my_logger.critical('[coap sendrq function]' + str(e) + ' DATA: ' + str(data) + ' ADDRESS: ' + str(addr))

    def _port_listening(self):
        if(Memory_all.main_all_prints == True):
            print('[*Loop] [CoAP] [UDP], address {} and port {}'.format(self.ip,self.port))

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
                print('[coap]',not_tuple_addr)

                if ((self.SearchMemory(not_tuple_addr)) == None ):
                    if(Memory.flag_print == True):
                        print('[*MEMORY] Not ip ')

                    #first add memory
                    self.AddIpMemory(not_tuple_addr, 1, datetime.datetime.now(), datetime.datetime.now(), str(data))

                    #verify ignore dictionay
                    worker = Ig(not_tuple_addr)
                    b = worker.run()

                    if(b == True):
                        print('[coap] Ignore dict [add]', not_tuple_addr)
                    else:
                        try:
                            self.sendrq(data, addr)
                            # FORWARD AKI COM PROBLEMA

                        except Exception as e:
                            print('Error coap Lookup 1', e)
                            self.my_logger.critical('[Error coap in Lookup 1]' + str(e))
                            continue

                else:
                    if(Memory.flag_print == True):
                        print ('[*MEMORY] True')
                    self.UpdateMemory(not_tuple_addr)

                    if(self._i_must_answer(not_tuple_addr) == True):
                        try:
                            self.sendrq(data, addr)
                            # FORWARD AKI COM PROBLEMA

                        except Exception as e:
                            print('Error coap Lookup 2', e)
                            self.my_logger.critical('[Error coap in Lookup 2]' + str(e))
                            continue

                #count to use in _control_clean_dict
                Memory._count_use+=1

                if(Memory._count_use > 1000000000):
                    if(Memory.flag_print == True):
                        print('[*MEMORY] _count_use = 1')
                    self.my_logger.warning('[coap _port_listening _count_use]' + str(Memory._count_use))
                    Memory._count_use = 1
                    print(Memory._count_use)


            except KeyboardInterrupt:
                self.socks.close()
                self.my_logger.error('[coap KeyboardInterrupt]')
                break

            except Exception as e:
                print('[coap _port_listening function]',e)
                print('[coap _port_listening', datetime.datetime.now(), data, addr)

                self.my_logger.critical('[coap _port_listening function]' + str(e) + ' DATA: ' + str(data) + ' ADDRESS: ' + str(addr))

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
            db_name = 'database/dnstor_statistics_coap.sqlite'

            _background_dict_ = DB_DNSTor(db_name, self.ip, self.port, self.my_logger)
            _background_dict_._run_db()

        except KeyboardInterrupt:
            print('[*THREAD] _supe_thread Stop [coap]')
            self.my_logger.error('[*THREAD] _supe_thread Stop [coap] KeyboardInterrupt')

        except Exception as e:
            print('[coap _supe_thread function]',e)
            self.my_logger.critical('[coap _supe_thread function]' + str(e))

    def run(self):
        try:
            if(Memory.flag_print == True):
                print('[*LOADING CoAP]')
            time.sleep(1)
            t2 = Thread(target=self._port_listening)
            t2.start()

        except KeyboardInterrupt:
            print('[*RUN] Stop working? Thread problem [coap]')
            self.my_logger.error('[coap Run function KeyboardInterrupt]')

        except Exception as e:
            print('[coap Run function]',e)
            self.my_logger.critical('[coap Run function]' + str(e))
