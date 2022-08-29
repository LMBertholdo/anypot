#!/usr/bin/env python
# -*- coding: utf-8 -*-

from threading import Thread, RLock
from datetime import datetime

from ssdp_.db import DB_DNSTor
from ssdp_.memory import Memory
from ssdp_.ignore import Ig, Modify_ip, Hour_verify, Creat_dict_ig, Ignore_dict

from memory_all import Memory_all

import argparse
import socket
import sqlite3
import threading
import datetime
import time
import select
import subprocess

class Dict_ssdp():

    LOCATION_MSG = ('HTTP/1.1 200 OK\r\n' +'ST: ALGO:ALGO\r\n''USN: 127.0.0.1:7766\r\n'+'Location: \r\n'+'Cache-Control: max-age=900\r\n'+'Server:Allegro-Software-RomUpnp/4.07 UPnP/1.0 IGD/1.00\r\n'+'Ext:\r\n\r\n')

    #server linux
    M_SEARCH_MSG = ('HTTP/1.1 200 OK\r\n' + 'CACHE-CONTROL: max-age=1810\r\n' + datetime.datetime.now().strftime('DATE: %a, %d %b %Y %X GMT\r\n') + 'EXT:\r\n'+'LOCATION:http://192.168.1.23:49156/details.xml\r\n' + 'SERVER: Linux/2.x.x, UPnP/1.0, pvConnect UPnP SDK/1.0, TwonkyMedia UPnP SDK/1.1\r\n' + 'ST: upnp:rootdevice\r\n' + 'USN: uuid:3d64febc-ae6a-4584-853a-85368ca80800::upnp:rootdevice\r\n' + '\r\n')

    #server printer
    NOTIFY_MSG = ('HTTP/1.1 200 OK\r\n' + 'HOST: 239.255.255.250:1900\r\n' + 'CACHE-CONTROL: max-age=60\r\n' + 'LOCATION: http://192.168.1.23:5200/Printer.xml\r\n'+'NT: urn:schemas-upnp-org:service:PrintBasic:\r\n' + 'NTS: ssdp:alive\r\n' + 'SERVER: Network Printer Server UPnP/1.0 os 1.03.04.02 12-21-2007\r\n'+'USN: uuid:Dell-Printer-1_9-dsi-secretariat::urn:schemas-upnp-org:service:PrintBasic:1\r\n' + '\r\n')

    #server printer
    ERROR_MSG = ('HTTP/1.1 500 Internal Server Error\r\n' + 'TRANSFER-ENCODING: \"chunked\"\r\n' + 'CONTENT-TYPE: text/xml; charset=\"utf-8\"\r\n' + datetime.datetime.now().strftime('DATE: %a, %d %b %Y %X GMT\r\n') + 'SERVER: Network Printer Server UPnP/1.0 os 1.03.04.02 12-21-2007\r\n' + '\n\r')

class Proxy_ssdp(object):
    """
    Main class of ssdp honeypot
    """

    def __init__(self, bind_address, bind_port, my_logger):
        self.port = bind_port
        self.ip = bind_address
        self.my_logger = my_logger

        #KEY WORDS
        self.msearch = 'M-SEARCH'
        self.notify = 'NOTIFY'

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
                print("[ssdp] This index does not exist!")
                self.my_logger.critical('[ssdp UpdateMemory function IndexError]')
            except KeyError:
                print("[ssdp] This key is not in the dictionary!")
                self.my_logger.critical('[ssdp UpdateMemory function KeyError]')
            except TypeError:
                print("[ssdp] Object does not support (tuple problem)")
                self.my_logger.critical('[ssdp UpdateMemory function TypeError]')
            except Exception as e:
                print('[ssdp UpdateMemory function]',e)
                self.my_logger.critical('[ssdp UpdateMemory function]' + str(e))

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

    def send_to(self, socks, addr, data):
        try:
            socks.sendto(bytes(data.encode('utf-8')),addr)

        except Exception as a:
            print('[ssdp send_to]', a)
            self.my_logger.critical('[ssdp send_to function]' + str(a))

    def send_ssdp(self, socks, addr, data):
        try:
            if(self.msearch in data.decode('utf-8')):
                self.send_to(socks,addr,Dict_ssdp.M_SEARCH_MSG)
                if(Memory.flag_print == True):
                    print(datetime.datetime.now(),'[ssdp] send M-SEARCH', addr)

            elif(self.notify in data.decode('utf-8')):
                self.send_to(socks,addr,Dict_ssdp.NOTIFY_MSG)
                if(Memory.flag_print == True):
                    print(datetime.datetime.now(),' [ssdp] send NOTIFY', addr)

            else:
                self.send_to(socks,addr,Dict_ssdp.ERROR_MSG)
                if(Memory.flag_print == True):
                    print(datetime.datetime.now(),'[ssdp] not classify input', addr, data)

        except Exception as b:
            print('[ssdp] send_ssdp function data input error',b)
            self.my_logger.critical('[ssdp send_ssdp function data input error]' + str(b))

    def _port_listening(self):
        if(Memory_all.main_all_prints == True):
            print('[*Loop] [SSDP] [UDP], address {} and port {}'.format(self.ip,self.port))

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
                print('[ssdp]',not_tuple_addr)

                if ((self.SearchMemory(not_tuple_addr)) == None ):
                    if(Memory.flag_print == True):
                        print('[*MEMORY] Not ip ')

                    #first add memory
                    self.AddIpMemory(not_tuple_addr, 1, datetime.datetime.now(), datetime.datetime.now(), str(data))

                    #verify ignore dictionay
                    worker = Ig(not_tuple_addr)
                    b = worker.run()

                    if(b == True):
                        print('[ssdp] Ignore dict [add]', not_tuple_addr)
                    else:
                        self.send_ssdp( self.socks, addr, data)

                else:
                    if(Memory.flag_print == True):
                        print ('[*MEMORY] True')
                    self.UpdateMemory(not_tuple_addr)

                    if(self._i_must_answer(not_tuple_addr) == True):

                        self.send_ssdp( self.socks, addr, data)

                #count to use in _control_clean_dict
                Memory._count_use+=1

                if(Memory._count_use > 1000000000):
                    if(Memory.flag_print == True):
                        print('[*MEMORY] _count_use = 1')
                    self.my_logger.warning('[ssdp _port_listening _count_use]' + str(Memory._count_use))
                    Memory._count_use = 1
                    print(Memory._count_use)

            except KeyboardInterrupt:
                self.socks.close()
                self.my_logger.error('[ssdp KeyboardInterrupt]')
                break

            except Exception as e:
                print('[ssdp _port_listening function]',e)
                self.my_logger.critical('[ssdp _port_listening function]' + str(e) + ' DATA: ' + str(data) + ' ADDRESS: ' + str(addr))

    def _supe_thread(self):
        try:
            #time.sleep(60* (Memory.time_thread_clean_dict))
            time.sleep(1)
            if(Memory.flag_print == True):
                print('[*THREAD] Clean dict')
            #print(Memory.dicio)

            #define DB name
            db_name = 'database/dnstor_statistics_ssdp.sqlite'

            _background_dict_ = DB_DNSTor(db_name, self.ip, self.port, self.my_logger)
            _background_dict_._run_db()

        except KeyboardInterrupt:
            print('[*THREAD] _supe_thread Stop [SSDP]')
            self.my_logger.error('[*THREAD] _supe_thread Stop [ssdp] KeyboardInterrupt')

        except Exception as e:
            print('[ssdp _supe_thread function]',e)
            self.my_logger.critical('[ssdp _supe_thread function]' + str(e))

    def run(self):
        try:
            if(Memory.flag_print == True):
                print('[*LOADING SSDP]')
            time.sleep(1)
            t2 = Thread(target=self._port_listening)
            t2.start()

        except KeyboardInterrupt:
            print('[*RUN] Stop working? Thread problem [ssdp]')
            self.my_logger.error('[ssdp Run function KeyboardInterrupt]')

        except Exception as e:
            print('[ssdp Run function]',e)
            self.my_logger.critical('[ssdp Run function]' + str(e))
