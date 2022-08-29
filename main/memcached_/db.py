#!/usr/bin/env python
# -*- coding: utf-8 -*-

from datetime import datetime
from threading import Thread

from memcached_.memory import Memory
from memory_all import Memory_all

import dateutil.parser #_insert_dict()
import sqlite3
import socket
import time
import psutil
import os
import threading
import datetime

class DB_DNSTor:
    """
    Main database for memcached honeypot
    """
    def __init__(self, i_name, i_bind_address, i_bind_port, my_logger):

        self.my_logger = my_logger

        self.conn = sqlite3.connect(i_name, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._create_tables()

        self.name = i_name
        self.bind_address = i_bind_address
        self.bind_port = i_bind_port

    def _run_db(self):
        try:
            if(Memory.flag_print == True):
                print('[*DB]')

            self._insert_basic(self.bind_address, self.bind_port)

            self._clean_dict()

        except Exception as e:
            print('[memcached _run_db function]',e)
            self.my_logger.critical('[memcached _run_db function]' + str(e))

    def _create_tables(self):
        try:
            if(Memory.flag_print == True):
                print('[*DB] Create database')
            cur = self.conn.cursor()
            cur.execute('''CREATE TABLE IF NOT EXISTS MEMCACHED_BASIC_CONFIG
                (
                     bind_address   text    NOT NULL
                    ,bind_port  text    NOT NULL
                    ,date_start text    NOT NULL
                )
                ;''')

            cur.execute('''CREATE TABLE IF NOT EXISTS MEMCACHED_MEMORY_DICT
                (
                     ip   text    NOT NULL
                    ,count  integer    NOT NULL
                    ,tempoInicio text    NOT NULL
                    ,tempoFinal   text    NOT NULL
                    ,payloadID integer NOT NULL
                )
                ;''')

            cur.execute('''CREATE TABLE IF NOT EXISTS MEMCACHED_IGNORE_IP_DICT
                (
                     ip   text    NOT NULL
                    ,sufixo  text    NOT NULL
                    ,ref text NOT NULL
                )
                ;''')

            cur.execute('''CREATE TABLE IF NOT EXISTS MEMCACHED_PAYLOAD_DICT
                (
                     payloadID   integer    NOT NULL
                    ,payload  text    NOT NULL
                )
                ;''')

            self.conn.commit()
            cur.close()

        except Exception as e:
            print('[memcached _create_tables function]',e)
            self.my_logger.critical('[memcached _create_tables function]' + str(e))

    def _insert_basic_verify(self,bind_address):
        try:
            cur = self.conn.cursor()

            cmdSelect = '''SELECT bind_address FROM MEMCACHED_BASIC_CONFIG limit 1;'''
            cur.execute(cmdSelect, {'bind_address':bind_address})
            rowDB = cur.fetchone()

            if(rowDB == None):
                cur.close()
                return True
            else:
                cur.close()
                return False

        except Exception as e:
            print('[memcached _insert_basic_verify function]',e)
            self.my_logger.critical('[memcached _insert_basic_verify function]' + str(e))

    def _insert_basic(self, bind_address, bind_port):
        try:
            if(self._insert_basic_verify(self.bind_address) == True):
                self.insert_basic_config(bind_address, bind_port)
                self.insert_ignore_ip()

        except Exception as e:
            print('[memcached _insert_basic function]',e)
            self.my_logger.critical('[memcached _insert_basic function]' + str(e))

    def insert_basic_config(self,bind_address, bind_port):
        try:
            cur = self.conn.cursor()
            varStore = '''INSERT OR REPLACE INTO MEMCACHED_BASIC_CONFIG (bind_address,bind_port,date_start) VALUES(:bind_address,:bind_port,:date_start);'''
            cur.execute(varStore, {'bind_address':bind_address ,'bind_port':bind_port , 'date_start':datetime.datetime.now()})
            self.conn.commit()
            cur.close()

        except Exception as e:
            print('[memcached insert_basic_config function]',e)
            self.my_logger.critical('[memcached insert_basic_config function]' + str(e))

    def insert_ignore_ip(self):
        try:
            cur = self.conn.cursor()

            for i in range(len(Memory.sufixo)):

                # here call lookup_ignore

                varStore = '''INSERT OR REPLACE INTO MEMCACHED_IGNORE_IP_DICT
                (ip,sufixo,ref)
                VALUES(:ip,:sufixo,:ref);'''
                cur.execute(varStore,{'ip':'0','sufixo':Memory.sufixo[i],'ref':Memory.ref[i]})
                self.conn.commit()

            cur.close()

        except Exception as e:
            print('[memcached insert_ignore_ip function]',e)
            self.my_logger.critical('[memcached insert_ignore_ip function]' + str(e))

    def lookup_ignore(self, name):
        try:
            #here go the lookup to get the ip address
            if(Memory.flag_print == True):
                print('lookup ignore ip')

        except Exception as e:
            print('[memcached lookup_ignore function]',e)
            self.my_logger.critical('[memcached lookup_ignore function]' + str(e))

    def _clean_dict(self):
        try:
            if(Memory.flag_print == True):
                print('[*DICT] Try clean')

            if(self._control_clean_dict() == True):#verify dict use by the system
                _tmpip_list = self._verify_time_of_last_dict_use()# return ip with 5 minutos or more between start and end, to remove the data and insert into the database

                if(Memory.flag_print == True):
                    print('[*DICT_list:]')
                    print(_tmpip_list)

                for index in range(len(_tmpip_list)):
                    try:
                        Memory.lock.acquire()
                        self._insert_dict(_tmpip_list[index])
                    finally:
                        Memory.lock.release()
                        if(self._control_clean_dict() != True):
                            break
            else:
                if(Memory.flag_print == True):
                    print('[*DICT] waiting to clean dict')

        except Exception as e:
            print('[memcached _clean_dict function]',e)
            self.my_logger.critical('[memcached _clean_dict function]' + str(e))

    #function for verify cpu and memory use
    def _control_clean_dict(self):
        try:
            #get pid
            p = psutil.Process(os.getpid())

            #if(p.num_threads() < 4 and p.cpu_percent(interval=1) <= 0.0):
            if(p.num_threads() < Memory_all.number_threads and self._verify__count_use() == True):
                #without work
                return True
            else:
                return False

        except Exception as e:
            print('[memcached _control_clean_dict function]',e)
            self.my_logger.critical('[memcached _control_clean_dict function]' + str(e))

    def _verify__count_use(self):

        try:
            t1 = Memory._count_use
            time.sleep(3)
            t2 = Memory._count_use

            if(t1 == t2 or t1 <= (t2+20)):
                return True
            else:
                return False

        except Exception as e:
            print('[memcached _verify__count_use function]',e)
            self.my_logger.critical('[memcached _verify__count_use function]' + str(e))

    def searchPayloads(self, payloadSearch):
        try:
            # CHANGE OLD TABLES with
            # alter table MEMCACHED_MEMORY_DICT add payloadID status integer default '-1' ;

            cur = self.conn.cursor()

            tValue = (str(payloadSearch), )
            cur.execute('''SELECT payloadID FROM MEMCACHED_PAYLOAD_DICT where payload LIKE ? limit 1;''', tValue)
            rowDB = cur.fetchone()
            # print(rowDB[0])

            if(rowDB == None):
                cmdSelect = '''SELECT payloadID FROM MEMCACHED_PAYLOAD_DICT order by payloadID DESC limit 1;'''
                cur.execute(cmdSelect)
                lastID = cur.fetchone()

                if(lastID == None):
                    lastID = 1
                else:
                    lastID = int(lastID[0]) + 1

                if(Memory.flag_print == True):
                    print('[memcached New ID]:', lastID)

                # Insert new key and payload
                iValue = (int(lastID), str(payloadSearch), )
                cur.execute('''INSERT INTO MEMCACHED_PAYLOAD_DICT VALUES (?,?)''', iValue)
                self.conn.commit()

                cur.close()
                return int(lastID)
            else:
                cur.close()
                if(Memory.flag_print == True):
                    print('[memcached Found ID]:', rowDB[0])

                return int(rowDB[0])

        except Exception as e:
            print('[memcached searchPayloads function]',e)
            self.my_logger.critical('[memcached searchPayloads function]' + str(e))
            cur.close()
            return int(-1)

    #function remove and insert data on DB
    def _insert_dict(self,ip):

        try:
            ip = ip
            count = Memory.dicio[ip][0]
            tempoInicio = Memory.dicio[ip][1]
            tempoFinal = Memory.dicio[ip][2]
            payloadID = self.searchPayloads(str(Memory.dicio[ip][3]))

            Memory.lock.acquire()
            cur = self.conn.cursor()
            varStore = '''INSERT INTO MEMCACHED_MEMORY_DICT (ip,count,tempoInicio,tempoFinal,payloadID) VALUES(:ip,:count,:tempoInicio,:tempoFinal,:payloadID);'''
            cur.execute(varStore, {'ip':ip ,'count':count ,'tempoInicio':tempoInicio , 'tempoFinal':tempoFinal,'payloadID':payloadID})

            #remove key for update count value
            del Memory.dicio[ip]
            self.conn.commit()
            cur.close()

        except Exception as e:
            print('[memcached _insert_dict function]',e)
            self.my_logger.critical('[memcached _insert_dict function]' + str(e))

        finally:
            Memory.lock.release()
            if(Memory.flag_print == True):
                print('[*DICT_CLEAN]')

    def _verify_time_of_last_dict_use(self):
        try:
            if(Memory.flag_print == True):
                print('[*GET_LIST] dict ip list')
            #Function that will check the dates and teronar a list with the keys to be removed
            _now_time = datetime.datetime.now()
            ip_list = []
            #https://stackoverflow.com/questions/2775864/python-create-unix-timestamp-five-minutes-in-the-future

            #old time plus 5 minutes, if the time is < than now, remove from the dict. So the key is add in the list
            for keys in Memory.dicio:
                last_time = Memory.dicio[keys][2]
                old = last_time + datetime.timedelta(minutes=Memory.time_clean_dict)
                if(old< _now_time):
                    ip_list.append(keys)

            return ip_list

        except Exception as e:
            print('[memcached _verify_time_of_last_dict_use function]',e)
            self.my_logger.critical('[memcached _verify_time_of_last_dict_use function]' + str(e))
