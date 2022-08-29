#!/usr/bin/env python
# -*- coding: utf-8 -*-

from threading import Thread, RLock
from memory_all import Memory_all

class Memory(object):
    """
    Local memory for cldap
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

    #Thread
    timeout = Memory_all.timeout_thread

    time_clean_dict = Memory_all.time_clean_dict

    sufixo = ['']

    ref = ['']
