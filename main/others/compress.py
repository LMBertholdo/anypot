#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import glob
import time
import datetime

# https://askubuntu.com/questions/62492/how-can-i-change-the-date-modified-created-of-a-file#62496
# touch -d "38 hours ago" filename

class Compress(object):
    """
    Compress class is responsible to compress all the .pcaps files in /tcpdump_/pcap_file/
    """
    def __init__(self, my_logger):
        self.folder = './tcpdump_/pcap_file/'
        self.print_flag = True
        self.days_to_subtract = 1
        self.time_loop = 3600
        self.my_logger = my_logger

    def build_dir(self):
        try:
            files = filter(os.path.isfile, glob.glob(self.folder + "*" ) )
            file_filter = [f for f in files if('.bz2' not in f and '.txt' not in f)]

            self.result_files = sorted(file_filter, key=os.path.getmtime)

        except Exception as e:
            print('[Compress build_dir function]',e)
            self.my_logger.critical('[Compress build_dir function]' + str(e))

    def compressPcap(self, name):
        try:
            string = 'bzip2 ' + str(name)
            os.system(string)

        except Exception as e:
            print('[Compress compressPcap function]',e)
            self.my_logger.critical('[Compress compressPcap function]' + str(e))

    def verify_size_time(self, file, day):
        try:
            if(self.print_flag == True):
                print(file)
            (mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime) = os.stat(file)

            new_time = datetime.datetime.strptime(time.ctime(mtime), "%a %b %d %H:%M:%S %Y")
            if(size > 100000000 and new_time < day):
                if(self.print_flag == True):
                    print('Compress file:', file)
                self.compressPcap(file)

        except Exception as e:
            print('[Compress verify_size_time function]',e)
            self.my_logger.critical('[Compress verify_size_time function]' + str(e))

    def verify(self):
        while(True):
            try:
                self.build_dir()
                # now = datetime.datetime.now()
                yesterday = datetime.datetime.now() - datetime.timedelta(days=self.days_to_subtract)

                if(self.print_flag == True):
                    print('File list:', self.result_files)

                if(len(self.result_files) > 1):
                    for each in self.result_files:
                        self.verify_size_time(each, yesterday)

                # Sleep
                time.sleep(self.time_loop)
            except Exception as e:
                print('[Compress verify function]', e)
                self.my_logger.critical('[Compress verify function]' + str(e))
