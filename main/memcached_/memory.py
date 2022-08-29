#!/usr/bin/env python
# -*- coding: utf-8 -*-

from threading import Thread, RLock

from memory_all import Memory_all

class Memory(object):
    """
    Local memory memcached
    """

    #Flag print
    flag_print = Memory_all.flag_print

    #Memory dictionary
    #global dicio
    dicio = dict()

    #global lock
    lock = RLock()

    insert_lock = RLock()

    #global _count_use
    _count_use = 0

    #NUMER MAX of response
    count_max = Memory_all.value

    #time _verify_time_of_last_dict_use
    time_clean_dict = Memory_all.time_clean_dict

    #time sleep thread
    #time_thread_clean_dict = 1 #minutes

    #Thread
    timeout = Memory_all.timeout_thread

    sufixo = ['']

    ref = ['']
