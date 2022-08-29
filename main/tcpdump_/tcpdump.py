#!/usr/bin/env python
# -*- coding: utf-8 -*-

import subprocess as sub

import time
import datetime
import os

from memory_all import Memory_all

class Tcpdump(object):
    """
    TCPDUMP class will capture package using tcpdump.
    """
    def __init__(self):
        #Host ip address
        self.addr = '192.168.0.120'

        self.port = ' 17 or port 19 or port 53 or port 123 or port 1900 or port 11211 or port 27105 or port 5683'

        self.file_path = './tcpdump_/pcap_file/tcpdump.out.'
        self.file_date = str(datetime.datetime.now()).replace(' ','_').replace(':','-')
        self.file_format = '_dcn.pcap'
        self.file_full_name = self.file_path+self.file_date+self.file_format
        self.abort = False
        self.info = Memory_all.flag_print #False #print info

        #self.tcpdump_interface = 'lo'
        self.tcpdump_interface = 'eth0'
	#self.tcpdump_interface = 'enp0s31f6'

    def print_logo(self):
        print('-----------------------------------------------------------------------------')
        print('--------------------[Start] Tcpdump -----------------------------------------')
        print('-----------------------------------------------------------------------------')
        print('-- Remember this configuration it is manual, in the tcpdump.py file -----------')
        print('-----------------------------------------------------------------------------')
        print('-- script tcpdump v. 3.1.0  (this code) -------------------------------------')
        print('-- tcpdump v. 4.9.2 libpcap v. 1.8.1 OpenSSL 1.1.0g Nov 2017 ----------------')
        print('---------------------stdout=sub.PIPE-----------------------------------------')
        print('-----------------------------------------------------------------------------')


    def run_tcpdump(self):
        time.sleep(1)
        if(self.info == True):
            self.print_logo()
        try:

            if(os.path.exists(str('/usr/sbin/tcpdump')) == True):
                self.tcpdump_path = '/usr/sbin/tcpdump'

            elif(os.path.exists(str('/bin/tcpdump')) == True):
                self.tcpdump_path = '/bin/tcpdump'

            else:
                print('[WARNING ....]')
                print('[TCPDUMP] not Found')
                self.abort = True


            if(self.abort == False):
                try:
                    if(Memory_all.main_all_prints):
                        print('\n[TCPDUMP] Basic info:\n\__Interface ',self.tcpdump_interface,'\n\__Port',self.port,'\n\__Tcpdump path',self.tcpdump_path,'\n\__File',self.file_full_name,'\n')

                    p = sub.Popen((str(self.tcpdump_path),'-i',str(self.tcpdump_interface),'port',str(self.port) ,'-W 99999999', '-C','100','-w',str(self.file_full_name)),stdout=sub.PIPE)
                    #print(p)
                    p.wait()

                except Exception as a:
                    Memory_all.tcpdump_error = True
                    print('[TCPDUMP run_tcpdump function]',e)

        except KeyboardInterrupt:
            p.terminate()

        except Exception as e:
            print('[TCPDUMP run_tcpdump function]', e)
            Memory_all.tcpdump_error = True
