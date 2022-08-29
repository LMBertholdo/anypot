#!/usr/bin/env python
# -*- coding: utf-8 -*-

from threading import Thread, RLock

class Memory_all(object):
    """
    Memory_all is a class with basic information that each protocol will retrieve for their local memory. This class will receive innumerous configuration from .ini file or user input.
    """

    #Flag print
    flag_print = False

    #Steam print socket timeout (TCP Stuff...)
    flag_p = False

    #remove main flags (all protocols)
    main_flag_print = False

    #main_all_prints (just main_all class or configuration stuff)
    main_all_prints = False

    #signalkill messages
    kill_print = True

    #warning and except messagens print
    warning_print = True

    #time sleep thread
    time_thread_clean_dict = 1440 #minutes

    #verification time
    time_clean_dict = 1440 #minutes

    #time Ignore_dicts clean dict
    time_clean_ignore = 1440 # 1*60    = 60 seconds

    #NUMER MAX of response
    value = 5

    #number of threads for db.py class using in _control_clean_dict()
    #this ideia need change
    number_threads = 40

    #Thread
    timeout_thread = 15

    #DNS buffer recvfrom size
    buffer_dns = 8192

    #info clean_function
    chargen_bind_ip = ''
    chargen_bind_port = ''
    chargen_run = ''
    qotd_bind_ip = ''
    qotd_bind_port = ''
    qotd_path = ''
    qotd_run = ''
    steam_bind_ip = ''
    steam_run = ''
    memcached_bind_ip = ''
    memcached_bind_port = ''
    memcached_bind_ip_server = ''
    memcached_bind_port_server = ''
    memcached_run = ''
    tcpdump_run = ''
    bind_address = ''
    bind_port = ''
    unbound_server = ''
    unbound_port = ''
    ntp_bind_ip = ''
    ntp_bind_port = ''
    ntp_run = ''
    ssdp_bind_ip = ''
    ssdp_bind_port = ''
    ssdp_run = ''
    coap_bind_ip = ''
    coap_bind_port = ''
    coap_run = ''
    cldap_bind_ip = ''
    cldap_bind_port = ''
    cldap_run = ''

    tcpdump_error = False

    #signal URS01
    #time each listening thread will sleep
    time_signal_sleep = 600 #10 minutes

    #try clean default
    default_try = 2 #>=2

    #flag in each listening to STOP
    listening_stop = False

    #Loop LOCK in Signal_clean
    dict_lock = False

    #Loop count in Signal_clean
    dict_lock_count = 0
