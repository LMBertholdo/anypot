#!/usr/bin/env python
# -*- coding: utf-8 -*-

from threading import Thread, RLock

from  memory_all import Memory_all

import datetime
import socket

class Ignore_dict(object):
    """
    This function is the memory dict
    """

    #dict use with 24h ignore
    h = dict()

    #dict use for always ignore
    ig = dict()

    #print ig flag
    ig_print_flag = Memory_all.flag_print

    #global lock
    lock = RLock()

class Creat_dict_ig(object):
    """
    This function creat the ig dict with all ip address
    """

    def __init__(self):
        self.sufixo = [
            'dnsresearch.cymru.com',
            'dnsscan.shadowserver.org',
            'openresolverproject.org',
            'openresolvertest.net',
            'satellite.cs.washington.edu',
            'syssec.rub.de'
            ]

        self.ip_list = []

    def print_dict(self):
        print('{} -- {} -- {}'.format('ID','STRING','INFO'))
        for i,value in enumerate(self.ip_list):
            print('{} -- {} -- {}'.format(i,value,Ignore_dict.ig[value]))


    def run(self):
        for i in range(len(self.sufixo)):
            if(Ignore_dict.ig_print_flag == True):
                print(self.sufixo[i])
            result = socket.getaddrinfo(self.sufixo[i],0,0,0,0)
            if(Ignore_dict.ig_print_flag == True):
                print(result[-2][4][0])
            self.ip_list.append(result[-2][4][0])
            date = datetime.datetime.now()
            Ignore_dict.ig[result[-2][4][0]] = (date, self.sufixo[i])

        if(Ignore_dict.ig_print_flag == True):
            self.print_dict()


class Hour_verify(object):
    """
    This function verify the time in the dictionary h, if time is bigger then 24h the ip address is remove from the dictionay
    """

    def __init__(self):
        self.list_id = []

    def verify(self):
        try:
            if(Ignore_dict.ig_print_flag == True):
                print('[Dict] Verify 24h ip')

            now = datetime.datetime.now()
            #print(now)
            #now = datetime.datetime(2018,2,13,10,30,1,1)
    #        nowday = now.day
    #        nowhour = now.hour

    #       get key list without lock in the dictionay
            for key in Ignore_dict.h.keys():
                if(Ignore_dict.ig_print_flag == True):
                    print(key)
                self.list_id.append(key)

    #       verify time
            for i,value in enumerate(self.list_id):
                #(0,'127.0.0.1')
                if(abs(now.day - Ignore_dict.h[value].day)>=2):
                    #call remove in value
                    if(Ignore_dict.ig_print_flag == True):
                        print('Day > 2')
                    func = Modify_ip(value)
                    func.Remove()

                elif(abs(now.day - Ignore_dict.h[value].day) == 1 and now.hour >= Ignore_dict.h[value].hour):
                    #call remove in value
                    if(Ignore_dict.ig_print_flag == True):
                        print('Day == 1 and hour >=')
                    func = Modify_ip(value)
                    func.Remove()

                else:
                    if(Ignore_dict.ig_print_flag == True):
                        print('IP:', value, ' time now (day,hour): ', now.day,now.hour, ' time in dict (day,hour): ', Ignore_dict.h[value].day,Ignore_dict.h[value].hour)

        except Exception as e:
            print('[ntp verify function]',e)


class Modify_ip(object):
    """
    This function modify information in the memory (dictionary h)
    """
    def __init__(self,ip):
        self.ip_addr = ip

    def AddIpMemory(self):
        try:
            Ignore_dict.lock.acquire()
            date = datetime.datetime.now()
            Ignore_dict.h[self.ip_addr] = (date)

        except Exception as e:
            print('[ntp AddIpMemory function]',e)

        finally:
            Ignore_dict.lock.release()

    def Remove(self):
        try:
            Ignore_dict.lock.acquire()
            del Ignore_dict.h[self.ip_addr]

        except Exception as e:
            print(e)

        finally:
            Ignore_dict.lock.release()

class  Ig(object):
    """
    This function just verify the dictionay and return a response to the program
    """

    def __init__(self,ip):
        self.ip_addr = ip

    def verify_time_ignore(self):
        try:
            if self.ip_addr in Ignore_dict.h:
                if(Ignore_dict.ig_print_flag == True):
                    print(self.ip_addr, Ignore_dict.h[self.ip_addr])
                return True
            else:
                return False

        except Exception as e:
            print('[ntp verify_time_ignore function]',e)

    def verify_always_ignore(self):
        try:
            if self.ip_addr in Ignore_dict.ig:
                if(Ignore_dict.ig_print_flag == True):
                    print(self.ip_addr, Ignore_dict.ig[self.ip_addr])
                return True
            else:
                return False

        except Exception as e:
            print('[ntp verify_always_ignore function]',e)

    #if any function return True the server should ignore the msg
    def run(self):
        if(Ignore_dict.ig_print_flag == True):
            print('[Verify] ip')

        if(Ignore_dict.ig_print_flag == True):
            print('First verify always ignore ip addr')

        a = self.verify_always_ignore()

        if(a == False):
            if(Ignore_dict.ig_print_flag == True):
                print('Second verify 24h ip list')

            return(self.verify_time_ignore())

        else:
            if(Ignore_dict.ig_print_flag == True):
                print('Always ignore')

            return True
