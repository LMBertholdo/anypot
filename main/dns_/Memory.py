#!/usr/bin/env python
# -*- coding: utf-8 -*-

from threading import Thread, RLock

import dnslib

from memory_all import Memory_all

class Memory(object):
    #qtypes define
    #https://en.wikipedia.org/wiki/List_of_DNS_record_types
    _qtypes = { 1:'A', 2:'NS', 5:'CNAME', 6:'SOA', 12:'PTR', 15:'MX', 16:'TXT', 17:'RP', 18:'AFSDB', 24:'SIG', 25:'KEY', 28:'AAAA', 29:'LOC', 33:'SRV', 35:'NAPTR', 36:'KX', 37:'CERT', 38:'A6',  39:'DNAME', 41:'OPT', 42:'APL', 43:'DS', 44:'SSHFP', 45:'IPSECKEY', 46:'RRSIG', 47:'NSEC', 48:'DNSKEY', 49:'DHCID', 50:'NSEC3', 51:'NSEC3PARAM', 52:'TLSA', 55:'HIP', 99:'SPF', 249:'TKEY', 250:'TSIG', 251:'IXFR', 252:'AXFR', 255:'ANY', 257:'TYPE257', 32768:'TA', 32769:'DLV',}

    #update for this
    _qtype = dnslib.QTYPE.reverse
    _class = dnslib.CLASS.reverse

    #recvfrom size buffer (default is 8192)
    buffer_size = Memory_all.buffer_dns

    #Flag print
    flag_print = Memory_all.flag_print

    #Memory dictionary
    #global dicio
    dicio = dict()

    #global lock
    lock = RLock()

    #global _count_use
    _count_use = 0

    ### Other config ###

    #NUMER MAX of response
    count_max = Memory_all.value

    #time _verify_time_of_last_dict_use
    time_clean_dict = Memory_all.time_clean_dict #minutes

    #time sleep thread
    time_thread_clean_dict = 1 #minutes

    #Eighty percent probability of server returning valid response
    prob_error = 80 #

    #Thread
    timeout = Memory_all.timeout_thread

    #ignore IP (scan)

    ignore_ip = dict()

    sufixo = [
    'dnsresearch.cymru.com',
    'dnsscan.shadowserver.org',
    'openresolverproject.org',
    'openresolvertest.net',
    'satellite.cs.washington.edu',
    'syssec.rub.de'
    ]

    ref = [
    'http://dnsresearch.cymru.com',
    'http://dnsscan.shadowserver.org',
    'http://openresolverproject.org',
    'http://openresolverproject.org',
    'http://satellite.cs.washington.edu',
    'http://scanresearch.syssec.rub.de'
    ]
