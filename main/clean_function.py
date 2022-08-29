#!/usr/bin/env python
# -*- coding: utf-8 -*-

import time
import datetime

from memory_all import Memory_all

#syslog class
from syslog_._syslog import SysLogDef

from chargen.main_chargen import Proxy_chargen
from chargen.ignore import Ig as chargen_Ig, Modify_ip as chargen_Modify_ip, Hour_verify as chargen_Hour_verify, Creat_dict_ig as chargen_Creat_dict_ig, Ignore_dict as chargen_Ignore_dict

from qotd.main_qotd import Proxy_qotd
from qotd.ignore import Ig as qotd_Iq, Modify_ip as qotd_Modify_ip, Hour_verify as qotd_Hour_verify, Creat_dict_ig as qotd_Creat_dict_ig, Ignore_dict as qotd_Ignore_dict

from steam_.main_steam import Run_ports

from memcached_.main_memcached import Proxy_memcached
from memcached_.ignore import Ig as memcached_Iq, Modify_ip as memcached_Modify_ip, Hour_verify as memcached_Hour_verify, Creat_dict_ig as memcached_Creat_dict_ig, Ignore_dict as memcached_Ignore_dict

from dns_.main_dns import Proxy_dns
from dns_.ignore import Ig as dns_Iq, Modify_ip as dns_Modify_ip, Hour_verify as dns_Hour_verify, Creat_dict_ig as dns_Creat_dict_ig, Ignore_dict as dns_Ignore_dict

from ntp_.main_ntp import Proxy_ntp
from ntp_.ignore import Ig as ntp_Iq, Modify_ip as ntp_Modify_ip, Hour_verify as ntp_Hour_verify, Creat_dict_ig as ntp_Creat_dict_ig, Ignore_dict as ntp_Ignore_dict

from ssdp_.main_ssdp import Proxy_ssdp
from ssdp_.ignore import Ig as ssdp_Iq, Modify_ip as ssdp_Modify_ip, Hour_verify as ssdp_Hour_verify, Creat_dict_ig as ssdp_Creat_dict_ig, Ignore_dict as ssdp_Ignore_dict

from coap_.main_coap import Proxy_coap
from coap_.ignore import Ig as coap_Iq, Modify_ip as coap_Modify_ip, Hour_verify as coap_Hour_verify, Creat_dict_ig as coap_Creat_dict_ig, Ignore_dict as coap_Ignore_dict

from cldap_.main_cldap import Proxy_cldap
from cldap_.ignore import Ig as cldap_Iq, Modify_ip as cldap_Modify_ip, Hour_verify as cldap_Hour_verify, Creat_dict_ig as cldap_Creat_dict_ig, Ignore_dict as cldap_Ignore_dict

class Clean_function(object):
    """
    Clean_function is responsible for cleaning the memory dictionary, this interaction will be held after a specific time and will consult each protocol thread, capturing information from memory that is no longer being used and inserting it in the database.
    """

    def __init__(self, my_logger):
        self.my_logger = my_logger

    def loop_clean(self):
        time.sleep(3)
        aux_flag = False
        if(Memory_all.flag_print == True):
            print('[Main_clean_loop]')
        self.my_logger.warning('[Main_clean_loop]')

        try:
            while True:
                #chargen and signal SIGUSR1 stop
                if(aux_flag == True):
                    if(Memory_all.dict_lock_count <= Memory_all.default_try):
                        time.sleep(5)
                        print('Call Dict clean Again [Try count:',Memory_all.dict_lock_count,' ]')
                        self.my_logger.warning('Call Dict clean Again [Try count: ' + str(Memory_all.dict_lock_count) + ' ]')
                    if(Memory_all.dict_lock_count > Memory_all.default_try):
                        Memory_all.dict_lock = False
                        print('[Dict clean is now over, system will sleep for 10 minutes (Waiting DICT_CLEAN LOCK)]')
                        self.my_logger.warning('[Dict clean is now over, system will sleep for 10 minutes (Waiting DICT_CLEAN LOCK)]')
                        time.sleep(60*10)
                        #in error case try fix honeypot
                        Memory_all.listening_stop = False

                    Memory_all.dict_lock_count+=1
                    print('\_Try Chargen')
                self.my_logger.warning('\_Try Chargen')
                if(Memory_all.main_flag_print == True):
                    print('[loop_clean] [Chargen]')
                self.my_logger.debug('[loop_clean] [Chargen]')
                clean_dict_chargen = Proxy_chargen(Memory_all.chargen_bind_ip, Memory_all.chargen_bind_port, self.my_logger)
                clean_dict_chargen._supe_thread()

                #qotd
                if(aux_flag == True):
                    print('\_Try QOTD')
                self.my_logger.warning('\_Try QOTD')
                if(Memory_all.main_flag_print == True):
                    print('[loop_clean] [qotd]')
                self.my_logger.debug('[loop_clean] [qotd]')

                clean_dict_qotd = Proxy_qotd(Memory_all.qotd_path,Memory_all.qotd_bind_ip, Memory_all.qotd_bind_port, self.my_logger)
                clean_dict_qotd._supe_thread()

                #steam
                if(aux_flag == True):
                    print('\_Try Steam')
                self.my_logger.warning('\_Try Steam')
                if(Memory_all.main_flag_print == True):
                    print('[loop_clean] [steam]')
                self.my_logger.debug('[loop_clean] [steam]')

                Proxy_steam = Run_ports(Memory_all.steam_bind_ip, self.my_logger)
                Proxy_steam._supe_thread()

                #Memcached
                if(aux_flag == True):
                    print('\_Try Memcached')
                self.my_logger.warning('\_Try Memcached')
                if(Memory_all.main_flag_print == True):
                    print('[loop_clean] [Memcached]')
                self.my_logger.debug('[loop_clean] [Memcached]')

                clean_dict_memcached = Proxy_memcached(Memory_all.memcached_bind_ip, Memory_all.memcached_bind_port, Memory_all.memcached_bind_ip_server, Memory_all.memcached_bind_port_server, self.my_logger)
                clean_dict_memcached._supe_thread()

                #dns
                if(aux_flag == True):
                    print('\_Try dns')
                self.my_logger.warning('\_Try dns')
                if(Memory_all.main_flag_print == True):
                    print('[loop_clean] [dns]')
                self.my_logger.debug('[loop_clean] [dns]')

                clean_dict_dns = Proxy_dns(Memory_all.dns_bind_ip, Memory_all.dns_bind_port, Memory_all.unbound_server, Memory_all.unbound_port, self.my_logger)
                clean_dict_dns._supe_thread()

                #ntp
                if(aux_flag == True):
                    print('\_Try ntp')
                self.my_logger.warning('\_Try ntp')
                if(Memory_all.main_flag_print == True):
                    print('[loop_clean] [ntp]')
                self.my_logger.debug('[loop_clean] [ntp]')

                clean_dict_ntp = Proxy_ntp(Memory_all.ntp_bind_ip,Memory_all.ntp_bind_port, self.my_logger)
                clean_dict_ntp._supe_thread()

                #ssdp
                if(aux_flag == True):
                    print('\_Try SSDP')
                self.my_logger.warning('\_Try SSDP')
                if(Memory_all.main_flag_print == True):
                    print('[loop_clean] [SSDP]')
                self.my_logger.debug('[loop_clean] [SSDP]')

                clean_dict_ssdp = Proxy_ssdp(Memory_all.ssdp_bind_ip,Memory_all.ssdp_bind_port, self.my_logger)
                clean_dict_ssdp._supe_thread()

                #coap
                if(aux_flag == True):
                    print('\_Try CoAP')
                self.my_logger.warning('\_Try CoAP')
                if(Memory_all.main_flag_print == True):
                    print('[loop_clean] [CoAP]')
                self.my_logger.debug('[loop_clean] [CoAP]')

                clean_dict_coap = Proxy_coap(Memory_all.coap_bind_ip,Memory_all.coap_bind_port, self.my_logger)
                clean_dict_coap._supe_thread()

                #cldap
                if(aux_flag == True):
                    print('\_Try cldap')
                self.my_logger.warning('\_Try cldap')
                if(Memory_all.main_flag_print == True):
                    print('[loop_clean] [cldap]')
                self.my_logger.debug('[loop_clean] [cldap]')

                clean_dict_cldap = Proxy_cldap(Memory_all.cldap_bind_ip,Memory_all.cldap_bind_port, self.my_logger)
                clean_dict_cldap._supe_thread()

                #signal
                if(Memory_all.listening_stop == True):
                    #this aux var, fix problem when the signal is receive in the middle of the loop_clean
                    aux_flag = True

                if(Memory_all.listening_stop == False):
                    if(Memory_all.main_all_prints == True):
                        print('[loop_clean] Try clean dicts at ', str(datetime.datetime.now()),'(status: end)')
                    self.my_logger.debug('[loop_clean] Try clean dicts at  (status: end)' + str(datetime.datetime.now()))
                    time.sleep(60* (Memory_all.time_thread_clean_dict))
                    if(Memory_all.main_all_prints == True):
                        print('[loop_clean] Try clean dicts ', str(datetime.datetime.now()),'(status: start)')
                    self.my_logger.debug('[loop_clean] Try clean dicts  (status: start)' + str(datetime.datetime.now()))

        except Exception as e:
            self.my_logger.critical('[clean_function loop_clean function]' + str(e))

    def run_clean(self):
        self.loop_clean()


class Ignore_dicts(SysLogDef):
    """
    Ignore_dicts is the class responsible for blacklisting the address for 24h.
    """

    def __init__(self, my_logger):
        self.my_logger = my_logger

    def creat_all_ignore_dict(self):
        try:
            if(Memory_all.main_flag_print == True):
                print('[clean_function] Creat_dict_ig')
            self.my_logger.debug('[clean_function] Creat_dict_ig')

            #chargen
            a = chargen_Creat_dict_ig()
            a.run()

            #qotd
            b = qotd_Creat_dict_ig()
            b.run()

            #steam don\'t send informations that's why he don\'t need ignore class

            #memcached
            c = memcached_Creat_dict_ig()
            c.run()

            #dns
            d = dns_Creat_dict_ig()
            d.run()

            #ntp
            e = ntp_Creat_dict_ig()
            e.run()

            #ssdp
            f = ssdp_Creat_dict_ig()
            f.run()

            #coap
            g = coap_Creat_dict_ig()
            g.run()

            #cldap
            h = cldap_Creat_dict_ig()
            h.run()

        except Exception as e:
            self.my_logger.critical('[clean_function creat_all_ignore_dict function]' + str(e))

    def creat_all_ignore_list(self):

        self.creat_all_ignore_dict()
        time.sleep(2)

        while True:
            try:

                if(Memory_all.main_flag_print == True):
                    print('[clean_function] Verify 24h ignore list')
                self.my_logger.debug('[clean_function] Verify 24h ignore list')

                #chargen
                a_chargen = chargen_Hour_verify()
                a_chargen.verify()

                #qotd
                b_qotd = qotd_Hour_verify()
                b_qotd.verify()

                #steam don\'t send informations that's why he don\'t need ignore class

                #memcached
                c_memcached = memcached_Hour_verify()
                c_memcached.verify()

                #dns
                d_dns = dns_Hour_verify()
                d_dns.verify()

                #ntp
                e_ntp = ntp_Hour_verify()
                e_ntp.verify()

                #ssdp
                f_ssdp = ssdp_Hour_verify()
                f_ssdp.verify()

                #coap
                g_coap = coap_Hour_verify()
                g_coap.verify()

                #cldap
                h_cldap = cldap_Hour_verify()
                h_cldap.verify()

                time.sleep(60 * (Memory_all.time_clean_ignore))

            except Exception as e:
                self.my_logger.critical('[clean_function creat_all_ignore_list function]' + str(e))

    def run_ignore(self):
        self.creat_all_ignore_list()
