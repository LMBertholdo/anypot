#!/usr/bin/env python
# -*- coding: utf-8 -*-

from memcached_.memory import Memory

import random

class Log_commands(object):
    """
    ....
    """
    pass

class Other_msg(object):
    """
    Verify recive msg
    """
    def __init__(self,package_info,address):
        self.data = str(package_info)
        self.address = address
        self.flag_print = Memory.flag_print

        #get and gets
        self.word_gets = 'b\'get'
        self.word_gats = 'b\'gat'
            #return END

        # Statistics
            # stats, stats items, stats slabs, stats sizes
        self.word_stats = 'stats'
            #return stats

        #application msg
        self.word_version = 'b\'version'
            #return VERSION ...

        self.word_flush_all = 'b\'flush_all'

    def fake_bool(self):
        #return random.choice([True, False])
        return bool(random.getrandbits(1))

    def run(self):
        if(self.flag_print == True):
            print('Data:', self.data)

        try:
            if (self.word_gets in self.data):
                if(self.flag_print == True):
                    print('receive b\'get or b\'gets')
                return False, "END\r\n"

            if (self.word_gats in self.data):
                if(self.flag_print == True):
                    print('receive b\'gat or b\'gats')
                return False, "END\r\n"

            elif (self.word_stats in self.data):
                if(self.flag_print == True):
                    print('receive b\'stats')
                return True, "ignore this msg"

            elif (self.word_version in self.data):
                if(self.flag_print == True):
                    print('receive b\'version')
                return False, "VERSION 1.4.25 Ubuntu\r\n"

            elif (self.word_flush_all in self.data):
                if(self.flag_print == True):
                    print('receive b\'flush_all')
                return False, "OK\r\n"

            else:
                value = self.fake_bool()
                if(value == True):
                    return False, "NOT_FOUND\r\n"
                else:
                    return False, "ERROR\r\n"

        except TypeError as a:
            print('[Warning] log_commands error | Data:', self.data,'| Address:', self.address, 'Error: ', a)
            return False, "ERROR\r\n"

        except Exception as e:
            print('[Memcached Warning] log_commands Exception', e)

        finally:
            if(self.flag_print == True):
                print('Check msg')
