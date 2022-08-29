#!/usr/bin/env python
# -*- coding: utf-8 -*-

from datetime import datetime
from dnslib import DNSRecord
from threading import Thread, RLock

from dns_.decision import Lookup
from dns_.db import DB_DNSTor
from dns_.Memory import Memory
from dns_.ignore import Ig, Modify_ip, Hour_verify, Creat_dict_ig, Ignore_dict

from memory_all import Memory_all

import argparse
import socket
import time
import subprocess
import signal
import select
import sqlite3
import threading
import datetime

class Proxy_dns(object):
    """
    DNSTor base DNS honeypot (honey-dns)
    """

    def __init__(self, bind_address, bind_port, unbound_server, unbound_port, my_logger):
        self.dns_server = unbound_server
        self.dns_port = unbound_port
        self.bind_address = bind_address
        self.bind_port = bind_port
        self.my_logger = my_logger

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

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
                print("[dns] This index does not exist!")
                self.my_logger.critical('[dns UpdateMemory function IndexError]')
            except KeyError:
                print("[dns] This key is not in the dictionary!")
                self.my_logger.critical('[dns UpdateMemory function KeyError]')
            except TypeError:
                print("[dns] Object does not support (tuple problem)")
                self.my_logger.critical('[dns UpdateMemory function TypeError]')
            except Exception as e:
                print('[dns UpdateMemory function]',e)
                self.my_logger.critical('[dns UpdateMemory function]' + str(e))

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
        #start loop for the server
        self.sock.bind((self.bind_address, self.bind_port))

        if(Memory_all.main_all_prints == True):
            print('[*Loop] [DNS] [UDP], address {} and port {} '.format(self.bind_address,self.bind_port))

        while True:
            try:
                #data, addr = self.sock.recvfrom(4096)
                rlist,wlist,xlist = select.select([self.sock],[],[],Memory.timeout)

                if rlist:
                    data, (addr, socket_port) = rlist[0].recvfrom(Memory.buffer_size)

                    #signal flag stop
                    if(Memory_all.dict_lock == True):
                        time.sleep(Memory_all.time_signal_sleep)

                    if(Memory.flag_print == True):
                        #print(data)
                        print(addr)
                        #print(socket_port)

                    print('[dns]',addr)

                    #addr[0] return ip of consult
                    if ((self.SearchMemory(addr)) == None ):
                        if(Memory.flag_print == True):
                            print('[*MEMORY] Not ip ')

                        self.AddIpMemory(addr, 1, datetime.datetime.now(), datetime.datetime.now(), str(data))

                        try:
                            serv = Lookup(data,self.dns_server,self.dns_port, self.my_logger)
                            response = serv.dns_lookup()
                            self.sock.sendto(response, (addr,socket_port))

                        except Exception as e:
                            print('Error DNS in Lookup 1', e)
                            self.my_logger.critical('[Error DNS in Lookup 1]' + str(e))
                            continue

                    else:
                        if(Memory.flag_print == True):
                            print ('[*MEMORY] True')

                        self.UpdateMemory(addr)

                        if(self._i_must_answer(addr) == True):
                            try:

                                serv = Lookup(data,self.dns_server,self.dns_port, self.my_logger)
                                response = serv.dns_lookup()
                                self.sock.sendto(response, (addr,socket_port))

                            except Exception as e:
                                print('Error DNS in Lookup 2', e)
                                self.my_logger.critical('[Error DNS in Lookup 2]' + str(e))
                                continue

                            if(Memory.flag_print == True):
                                print('[*SENT_MSG]')

                    #count to use in _control_clean_dict
                    Memory._count_use+=1

                    if(Memory._count_use > 1000000000):
                        if(Memory.flag_print == True):
                            print('[*MEMORY] _count_use = 1')
                        self.my_logger.warning('[dns _port_listening _count_use]' + str(Memory._count_use))
                        Memory._count_use = 1

            except KeyboardInterrupt:
                self.my_logger.error('[dns KeyboardInterrupt]')
                self._endDNSTor()

            except Exception as e:
                print('[dns _port_listening function]',e)
                print('[dns _port_listening', datetime.datetime.now(), data, addr)
                self.my_logger.critical('[dns _port_listening function]' + str(e) + ' DATA: ' + str(data) + ' ADDRESS: ' + str(addr))

            finally:
                pass

    def _supe_thread(self):
        try:
            #while True:
                #time.sleep(60* (Memory.time_thread_clean_dict))
            if(Memory.flag_print == True):
                print('[*THREAD] Clean dict')
            #print(Memory.dicio)
            #define DB name
            db_name = 'database/dnstor_statistics_dns.sqlite'

            _background_dict_ = DB_DNSTor(db_name, self.bind_address, self.bind_port, self.dns_server, self.dns_port, self.my_logger)

            _background_dict_._run_db()

        except KeyboardInterrupt:
            print('[*THREAD] _supe_thread Stop')
            self.my_logger.error('[*THREAD] _supe_thread Stop [dns] KeyboardInterrupt')

        except Exception as e:
            print('[dns _supe_thread function]',e)
            self.my_logger.critical('[dns _supe_thread function]' + str(e))

    def run(self):
        try:
            t2 = Thread(target=self._port_listening)
            t2.start()

        except KeyboardInterrupt:
            print('[*RUN] Stop working? Thread problem [dns]')
            self.my_logger.error('[dns Run function KeyboardInterrupt]')

        except Exception as e:
            print('[dns Run function]',e)
            self.my_logger.critical('[dns Run function]' + str(e))

    def _endDNSTor(self):
        #Close DNStor
        print('\n[*END] Service Close ...')
