#!/usr/bin/env python
# -*- coding: utf-8 -*-

#import ConfigParser #in python2.7
import configparser #python3
import io
import sys

class ConfigRead(object):
    """
    Class Configuration Honeypot, read .ini file, and get configuration for the system.
    """
    def __init__(self):
        pass

    #just change the input for the memory_all, others values will be change in the main_all clas
    def convert_any_2_bool(self, input_value):
        if (input_value.lower() in ('yes','true','t','y','1') ):
            return True
        elif (input_value.lower() in ('no','false','f','n','0')):
            return False
        else:
            raise ValueError('[Invalid Boolean Value] Reading config_file.ini Like:', input_value)

    def red_syslog(self):
        try:
            #syslog config
            config = configparser.ConfigParser()
            config.read('config_file/config_file.ini')

            #syslog
            file_syslog = config.get('syslog','level')

            return file_syslog

        except Exception as a:
            print('[Reading File config_file.ini], syslog',a)

    def read_data(self):
        #load config file
        try:
            config = configparser.ConfigParser()
            config.read('config_file/config_file.ini')

            #get honeypot version
            #file_honeypot_version = config.getfloat('version','honeypot_version') #float
            file_honeypot_version = config.get('version','honeypot_version')#string

            #chargen
            file_chargen_bind_ip = config.get('chargen','chargen_ip')
            file_chargen_bind_port = config.getint('chargen','chargen_port')
            file_chargen_run = config.get('chargen','chargen_run')

            #qotd
            file_qotd_bind_ip = config.get('qotd','qotd_ip')
            file_qotd_bind_port = config.getint('qotd','qotd_port')
            file_qotd_path = config.get('qotd','qotd_path')
            file_qotd_run = config.get('qotd','qotd_run')

            #steam
            file_steam_bind_ip = config.get('steam','steam_ip')
            file_steam_run = config.get('steam','steam_run')

            #debugging
            file_main_print = config.get('debugging','main_print')
            file_kill_print = config.get('debugging','kill_print')
            file_main_all_prints = config.get('debugging','main_all_prints')
            file_warning_print = config.get('debugging','warning_print')

            #memcached
            file_memcached_bind_ip = config.get('memcached','memcached_bind_ip')
            file_memcached_bind_port = config.getint('memcached','memcached_bind_port')
            file_memcached_bind_ip_server = config.get('memcached','memcached_bind_ip_server')
            file_memcached_bind_port_server = config.get('memcached','memcached_bind_port_server')
            file_memcached_run = config.get('memcached','memcached_run')

            #tcpdump
            file_tcpdump_run = config.get('tcpdump','tcpdump_run')

            #dns
            file_dns_bind_ip = config.get('dns','dns_bind_ip')
            file_dns_bind_port = config.getint('dns','dns_bind_port')
            file_unbound_bind_ip = config.get('dns','dns_unbound_ip')
            file_unbound_bind_port = config.getint('dns','dns_unbound_port')
            file_dns_run = config.get('dns','dns_run')

            #ntp
            file_ntp_bind_ip = config.get('ntp','ntp_ip')
            file_ntp_bind_port = config.getint('ntp','ntp_port')
            file_ntp_run = config.get('ntp','ntp_run')

            #ssdp
            file_ssdp_bind_ip = config.get('ssdp','ssdp_ip')
            file_ssdp_bind_port = config.getint('ssdp','ssdp_port')
            file_ssdp_run = config.get('ssdp','ssdp_run')

            #coap
            file_coap_bind_ip = config.get('coap','coap_ip')
            file_coap_bind_port = config.getint('coap','coap_port')
            file_coap_run = config.get('coap','coap_run')

            #cldap
            file_cldap_bind_ip = config.get('cldap','cldap_ip')
            file_cldap_bind_port = config.getint('cldap','cldap_port')
            file_cldap_run = config.get('cldap','cldap_run')

            #loadbar
            file_loadbar_flag = bool_val = config.getboolean('loadbar','loadbar_print')

            return file_honeypot_version, file_chargen_bind_ip, file_chargen_bind_port, file_chargen_run, file_qotd_bind_ip, file_qotd_bind_port, file_qotd_path, file_qotd_run, file_steam_bind_ip, file_steam_run, file_main_print, file_kill_print, file_main_all_prints, file_warning_print, file_memcached_bind_ip, file_memcached_bind_port, file_memcached_bind_ip_server, file_memcached_bind_port_server, file_memcached_run, file_tcpdump_run, file_dns_bind_ip, file_dns_bind_port, file_unbound_bind_ip, file_unbound_bind_port, file_dns_run, file_ntp_bind_ip, file_ntp_bind_port, file_ntp_run, file_ssdp_bind_ip, file_ssdp_bind_port, file_ssdp_run, file_coap_bind_ip, file_coap_bind_port, file_coap_run, file_cldap_bind_ip, file_cldap_bind_port, file_cldap_run, file_loadbar_flag

        except Exception as a:
            print('[Reading File config_file.ini], read_data',a)
