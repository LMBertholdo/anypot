#!/usr/bin/env python
# -*- coding: utf-8 -*-

try:
    from threading import Thread, RLock

    import argparse
    import threading
    import time
    import sys
    import logging
    import syslog
    import configparser #python3

except Exception as e:
    print ('Unmet dependency:',e)
    sys.exit(1)

try:
    #syslog class
    from syslog_._syslog import SysLogDef

    from signal_clean import *
    from memory_all import Memory_all
    from clean_function import Clean_function, Ignore_dicts
    from os_sys import Os_sys
    from config_file.config_honeypot import ConfigRead

    from tcpdump_.tcpdump import Tcpdump
    from chargen.main_chargen import Proxy_chargen
    from qotd.main_qotd import Proxy_qotd
    from steam_.main_steam import Run_ports
    from memcached_.main_memcached import Proxy_memcached
    from dns_.main_dns import Proxy_dns
    from ntp_.main_ntp import Proxy_ntp
    from ssdp_.main_ssdp import Proxy_ssdp
    from coap_.main_coap import Proxy_coap
    from others.compress import Compress
    from coap_.coap2 import * # background coap server
    from cldap_.main_cldap import Proxy_cldap

except Exception as e:
    print ('Import error:',e)
    sys.exit(1)

try:
    from tqdm import tqdm

except Exception as e:
    print ('Import error:',e)
    sys.exit(1)

class Main_honey(SysLogDef):
    """
    Main_honey honeypot function is responsible for launching all the threads needed for each protocol and will be in charge of global operations such as clean_function, signal_clean, os_sys, and memory_all. Protocols will be independent of one another BUT operations to stop the application or retrieve information from memory to be inserted in the database will be carried out by clean_function which in turn will be launched by Main_honey.
    """

    def __init__(self, print_loadbar, chargen_bind_address, chargen_bind_port, chargen_run, qotd_bind_address, qotd_bind_port, qotd_path, qotd_run, steam_bind_address, steam_run, main_print, kill_print, main_all_prints, warning_print, memcached_bind_address, memcached_bind_port, memcached_bind_ip_server, memcached_bind_port_server, memcached_run, tcpdump_run, dns_bind_address, dns_bind_port, unbound_server, unbound_port, dns_run, ntp_bind_address, ntp_bind_port, ntp_run, ssdp_bind_address, ssdp_bind_port, ssdp_run, coap_bind_address, coap_bind_port, coap_run, cldap_bind_address, cldap_bind_port, cldap_run, syslog_level):

        #start syslog
        self.syslog_level = syslog_level
        syslog_run = SysLogDef(self.syslog_level)
        self.my_logger = syslog_run.run()

        self.error_flag = False

        #verify types
        self.flag_print_loadbar = self.convert_str_2_bool(print_loadbar)

        if(self.flag_print_loadbar == True):
            self.pbar = tqdm(total=100,ascii=True,desc='Building Honeypot')

        #call_clean_function NEED THIS
        #Chargen
        Memory_all.chargen_bind_ip = chargen_bind_address
        Memory_all.chargen_bind_port = chargen_bind_port
        Memory_all.chargen_run = self.convert_str_2_bool(chargen_run)

        #qotd
        Memory_all.qotd_bind_ip = qotd_bind_address
        Memory_all.qotd_bind_port = qotd_bind_port
        Memory_all.qotd_path = qotd_path
        Memory_all.qotd_run = self.convert_str_2_bool(qotd_run)

        #Games or Steam
        Memory_all.steam_bind_ip = steam_bind_address
        Memory_all.steam_run = self.convert_str_2_bool(steam_run)

        #Memcached
        Memory_all.memcached_bind_ip = memcached_bind_address
        Memory_all.memcached_bind_port = memcached_bind_port
        Memory_all.memcached_bind_ip_server = memcached_bind_ip_server
        Memory_all.memcached_bind_port_server = memcached_bind_port_server
        Memory_all.memcached_run = self.convert_str_2_bool(memcached_run)

        #TCPDUMP
        Memory_all.tcpdump_run = self.convert_str_2_bool(tcpdump_run)

        #print flags
        Memory_all.kill_print = self.convert_str_2_bool(kill_print)

        Memory_all.main_all_prints = self.convert_str_2_bool(main_all_prints)

        Memory_all.warning_print = self.convert_str_2_bool(warning_print)

        Memory_all.main_flag_print = self.convert_str_2_bool(main_print)

        #dns
        Memory_all.dns_bind_ip = dns_bind_address
        Memory_all.dns_bind_port = dns_bind_port
        Memory_all.unbound_server = unbound_server
        Memory_all.unbound_port = unbound_port
        Memory_all.dns_run = self.convert_str_2_bool(dns_run)

        #ntp
        Memory_all.ntp_bind_ip = ntp_bind_address
        Memory_all.ntp_bind_port = ntp_bind_port
        Memory_all.ntp_run = self.convert_str_2_bool(ntp_run)

        #ssdp
        Memory_all.ssdp_bind_ip = ssdp_bind_address
        Memory_all.ssdp_bind_port = ssdp_bind_port
        Memory_all.ssdp_run = self.convert_str_2_bool(ssdp_run)

        #CoAP
        Memory_all.coap_bind_ip = coap_bind_address
        Memory_all.coap_bind_port = coap_bind_port
        Memory_all.coap_run = self.convert_str_2_bool(coap_run)

        #cldap
        Memory_all.cldap_bind_ip = cldap_bind_address
        Memory_all.cldap_bind_port = cldap_bind_port
        Memory_all.cldap_run = self.convert_str_2_bool(cldap_run)

        self.run_background_server() # coap background server

    def run_background_server(self):
        # https://stackoverflow.com/questions/55367538/how-to-execute-code-in-if-name-main-from-another-python-file
        try:
            dd()

        except Exception as e:
            self.my_logger.critical('[run_background_server function]' + str(e))
            print('[coap2 main loop run_background_server]', e)

    #verify type, best way of check user error
    def convert_str_2_bool(self, input_value):
        input_value = str(input_value)
        if (input_value.lower() in ('yes','true','t','y','1') ):
            return True
        elif (input_value.lower() in ('no','false','f','n','0')):
            return False
        else:
            self.my_logger.error('[Invalid Boolean Value] Like:', input_value)
            raise ValueError('[Invalid Boolean Value] Like:', input_value)

    def how_is_working(self):
        time.sleep(12)
        if(self.error_flag == True):
            self.my_logger.error('[List of online protocols] ERROR honeypot is not working')
            print('\n[List of online protocols] ERROR honeypot is not working')

        elif(Memory_all.tcpdump_error == True):
            self.my_logger.error('[List of online protocols] ERROR honeypot, TCPDUMP is not working')
            print('\n[List of online protocols] ERROR honeypot, TCPDUMP is not working')
            sys_config = Os_sys(self.my_logger)
            sys_config.current_pid()

        else:
            print('\n[List of online protocols]\n\___Chargen -->',Memory_all.chargen_run , '\n\___qotd --> ',Memory_all.qotd_run,'\n\___Steam [Games]-->',Memory_all.steam_run,'\n\___Memcached -->', Memory_all.memcached_run,'\n\___DNS -->', Memory_all.dns_run,'\n\___NTP -->', Memory_all.ntp_run,'\n\___SSDP -->', Memory_all.ssdp_run, '\n\___CoAP -->', Memory_all.coap_run, '\n\___CLDAP -->', Memory_all.cldap_run)
            sys_config = Os_sys(self.my_logger)
            sys_config.current_pid()

    def call_chargen(self):
        call_chargen = Proxy_chargen(Memory_all.chargen_bind_ip,Memory_all.chargen_bind_port, self.my_logger)
        call_chargen.run()

    def call_qotd(self):
        call_qotd = Proxy_qotd(Memory_all.qotd_path,Memory_all.qotd_bind_ip,Memory_all.qotd_bind_port, self.my_logger)
        call_qotd.run()

    def call_steam(self):
        Proxy_steam = Run_ports(Memory_all.steam_bind_ip, self.my_logger)
        Proxy_steam.worker()

    def call_memcached(self):
        call_memcached = Proxy_memcached(Memory_all.memcached_bind_ip, Memory_all.memcached_bind_port, Memory_all.memcached_bind_ip_server, Memory_all.memcached_bind_port_server, self.my_logger)
        call_memcached.run()

    def call_dns(self):
        call_dns = Proxy_dns(Memory_all.dns_bind_ip, Memory_all.dns_bind_port, Memory_all.unbound_server, Memory_all.unbound_port, self.my_logger)
        call_dns.run()

    def call_ntp(self):
        call_ntp = Proxy_ntp(Memory_all.ntp_bind_ip,Memory_all.ntp_bind_port, self.my_logger)
        call_ntp.run()

    def call_ssdp(self):
        call_ssdp = Proxy_ssdp(Memory_all.ssdp_bind_ip,Memory_all.ssdp_bind_port, self.my_logger)
        call_ssdp.run()

    def call_coap(self):
        call_coap = Proxy_coap(Memory_all.coap_bind_ip,Memory_all.coap_bind_port, self.my_logger)
        call_coap.run()

    def call_cldap(self):
        call_cldap = Proxy_cldap(Memory_all.cldap_bind_ip,Memory_all.cldap_bind_port, self.my_logger)
        call_cldap.run()

    def call_all(self):
        try:
            time.sleep(1)
            #chargen
            if(Memory_all.chargen_run == True):
                Th1 = Thread(target=self.call_chargen)
                Th1.start()
            else:
                if(Memory_all.warning_print == True):
                    print('[WARNING] Chargen honey it\'s not a default option, please type python main_all.py -h for more informations.')
                self.my_logger.warning('Chargen honey it\'s not a default option, please type python main_all.py -h for more informations.')
            #qotd
            if(Memory_all.qotd_run == True):
                Th2 = Thread(target=self.call_qotd)
                Th2.start()
            else:
                if(Memory_all.warning_print == True):
                    print('[WARNING] qotd honey it\'s not a default option, please type python main_all.py -h for more informations.')
                self.my_logger.warning('qotd honey it\'s not a default option, please type python main_all.py -h for more informations.')
            #steam
            if(Memory_all.steam_run == True):
                Th3 = Thread(target=self.call_steam)
                Th3.start()
            else:
                if(Memory_all.warning_print == True):
                    print('[WARNING] Steam honey it\'s not a default option, please type python main_all.py -h for more informations.')
                self.my_logger.warning('Steam honey it\'s not a default option, please type python main_all.py -h for more informations.')
            #memcached
            if(Memory_all.memcached_run == True):
                Th4 = Thread(target=self.call_memcached)
                Th4.start()
            else:
                if(Memory_all.warning_print == True):
                    print('[WARNING] Memcached honey it\'s not a default option, please type python main_all.py -h for more informations.')
                self.my_logger.warning('Memcached honey it\'s not a default option, please type python main_all.py -h for more informations.')
            #dns
            if(Memory_all.dns_run == True):
                Th5 = Thread(target=self.call_dns)
                Th5.start()
            else:
                if(Memory_all.warning_print == True):
                    print('[WARNING] DNS honey it\'s not a default option, please type python main_all.py -h for more informations.')
                self.my_logger.warning('DNS honey it\'s not a default option, please type python main_all.py -h for more informations.')
            #ntp
            if(Memory_all.ntp_run == True):
                Th6 = Thread(target=self.call_ntp)
                Th6.start()
            else:
                if(Memory_all.warning_print == True):
                    print('[WARNING] NTP honey it\'s not a default option, please type python main_all.py -h for more informations.')
                self.my_logger.warning('NTP honey it\'s not a default option, please type python main_all.py -h for more informations.')
            #ssdp
            if(Memory_all.ssdp_run == True):
                Th7 = Thread(target=self.call_ssdp)
                Th7.start()
            else:
                if(Memory_all.warning_print == True):
                    print('[WARNING] SSDP honey it\'s not a default option, please type python main_all.py -h for more informations.')
                self.my_logger.warning('SSDP honey it\'s not a default option, please type python main_all.py -h for more informations.')
            #CoAP
            if(Memory_all.coap_run == True):
                Th8 = Thread(target=self.call_coap)
                Th8.start()
            else:
                if(Memory_all.warning_print == True):
                    print('[WARNING] CoAP honey it\'s not a default option, please type python main_all.py -h for more informations.')
                self.my_logger.warning('CoAP honey it\'s not a default option, please type python main_all.py -h for more informations.')
            #cldap
            if(Memory_all.cldap_run == True):
                Th9 = Thread(target=self.call_cldap)
                Th9.start()
            else:
                if(Memory_all.warning_print == True):
                    print('[WARNING] cldap honey it\'s not a default option, please type python main_all.py -h for more informations.')
                self.my_logger.warning('cldap honey it\'s not a default option, please type python main_all.py -h for more informations.')

            if(self.flag_print_loadbar == True):
                self.pbar.update(30)


        except KeyboardInterrupt:
            self.my_logger.critical('[*RUN] Stop working? Thread problem [main]')

        except Exception as e:
            self.my_logger.critical('[main_all call_all function]',e)

        finally:
            if(Memory_all.kill_print == True):
                self.how_is_working()
            if(self.flag_print_loadbar == True):
                self.pbar.update(10)
                if(Memory_all.kill_print == True):
                    self.pbar.close()

    def call_clean_function(self):
        if(self.flag_print_loadbar == True):
            self.pbar.update(15)
        call_clean = Clean_function(self.my_logger)
        call_clean.run_clean()

    def call_ig(self):
        if(self.flag_print_loadbar == True):
            self.pbar.update(15)
        call_i = Ignore_dicts(self.my_logger)
        call_i.run_ignore()

    def call_tcpdump(self):
        time.sleep(5)
        if(self.flag_print_loadbar == True):
            self.pbar.update(30)
            if(Memory_all.kill_print == False):
                self.pbar.close()

        tcpdump_ = Tcpdump()
        tcpdump_.run_tcpdump()

    def run_compress(self):
        worker_c = Compress(self.my_logger)
        worker_c.verify()

    def periodic_flush(self):
        while True:
            sys.stdout.flush()
            time.sleep(30)

    def run(self):
        try:
            time.sleep(1)
            t1 = Thread(target=self.call_clean_function)
            t2 = Thread(target=self.call_all)
            t3 = Thread(target=self.call_ig)

            if(Memory_all.tcpdump_run == True):
                t4 = Thread(target=self.call_tcpdump)
            elif(Memory_all.tcpdump_run == False):
                print('[TCPDUMP] ***** Tcpdump Will not be executed *****')
                self.my_logger.warning('[TCPDUMP] ***** Tcpdump Will not be executed *****')
            else:
                if(Memory_all.warning_print == True):
                    print('[Warning] ***** TCPDUMP configuration is wrong *****s')
                    self.my_logger.warning('[TCPDUMP] ***** TCPDUMP configuration is wrong *****s')

            t5 = Thread(target=self.run_compress)
            t6 = Thread(target=self.periodic_flush)

            # Clean function
            t1.start()
            # All port listening
            t2.start()
            # All ignore dict in memory
            t3.start()
            # Need tcpdump for all
            if(Memory_all.tcpdump_run == True):
                t4.start()
            # Run compress File
            t5.start()
            # Flush output periodically
            t6.start()
        except KeyboardInterrupt:
            self.my_logger.critical('[*RUN] Stop working? Thread problem [main]')

        except Exception as e:
            self.my_logger.critical('[main_all run function]',e)


if __name__ == '__main__':

    #syslog
    get_syslog = ConfigRead()
    file_syslog = get_syslog.red_syslog()

    #ini file input configuration
    get_config = ConfigRead()
    file_honeypot_version, file_chargen_bind_ip, file_chargen_bind_port, file_chargen_run, file_qotd_bind_ip, file_qotd_bind_port, file_qotd_path, file_qotd_run, file_steam_bind_ip, file_steam_run, file_main_print, file_kill_print, file_main_all_prints, file_warning_print, file_memcached_bind_ip, file_memcached_bind_port, file_memcached_bind_ip_server, file_memcached_bind_port_server, file_memcached_run, file_tcpdump_run, file_dns_bind_ip, file_dns_bind_port, file_unbound_bind_ip, file_unbound_bind_port, file_dns_run, file_ntp_bind_ip, file_ntp_bind_port, file_ntp_run, file_ssdp_bind_ip, file_ssdp_bind_port, file_ssdp_run, file_coap_bind_ip, file_coap_bind_port, file_coap_run, file_cldap_bind_ip, file_cldap_bind_port, file_cldap_run, file_loadbar_flag = get_config.read_data()

    #second option
    #Basic info
    parser = argparse.ArgumentParser(description='This script will run a group of honeypots, that are made for capture traffic information and respond some types of messages that users/tools will send to him.\n The purpose of this tool is to capture traffic used for amplification attacks. \n\n\n (WARNING, by default all host will get the same IP address (from config_file.ini), if you have more interfaces you can change each ip address, just removing the old ip address from the file. This way you can chose what protocol will use what interface and the respective ip address.)') #,formatter_class=RawTextHelpFormatter)

    ###############
    ### WARNING ###
    ###############
    #by default all host will get the same IP address (from file in ./config_file/config_file.ini), if you have more interfaces you can change each ip address on config_file.ini file, or just removing the ip address variable from the requested parser.add_argument. This way you can chose what protocol will use what interface and the respective ip address. Or just set a variable like host_ip and use in the parser.add_argument.
    #host_ip = '127.0.0.1'
    #host_ip = '192.168.0.6'

    #version honeypot
    parser.add_argument('--version','-v','-vvv','-version', action='version', version=str(file_honeypot_version))

    #loadbar
    parser.add_argument('--print-loadbar', type=str, default=file_loadbar_flag, help='Boolean define if the loadbar will run or not. The default is True.')

    #chargen config
    parser.add_argument('--chargen-bind-ip', type=str, default=file_chargen_bind_ip, help='Address the server should bind to. The default is 127.0.0.1.')

    parser.add_argument('--chargen-bind-port', type=int, default=file_chargen_bind_port, help='Port the server should bind to. The default is 19. (TIP: other port that can be use is 1902)')

    parser.add_argument('--chargen-run', type=str, default=file_chargen_run, help='This option prevents that honey-chargen run. The default is yes.')

    #qotd config
    parser.add_argument('--qotd-bind-ip', type=str, default=file_qotd_bind_ip, help='Address the server should bind to.  The default is 127.0.0.1.')

    parser.add_argument('--qotd-bind-port', type=int, default=file_qotd_bind_port, help='Port the server should bind to. The default is 17.(TIP: other port that can be use is 1700)')

    parser.add_argument('--qotd-path', type=str, default=file_qotd_path, help='Path to the file with quotes.')

    parser.add_argument('--qotd-run', type=str, default=file_qotd_run, help='This option prevents that honey-qotd run. The default is yes.')

    #steam config
    parser.add_argument('--steam-bind-ip', type=str, default=file_steam_bind_ip, help='Address the server should bind to. The default is 127.0.0.1. The range of the server ports is define in main_steam.py.')

    parser.add_argument('--steam-run', type=str, default=file_steam_run, help='This option prevents that steam-honey run, type yes (--steam-run yes) for change this option. The honey-steam will not ignore any traffic, his functionality is only to capture traffic in a range of ports, that is use by steam users to run servers.')

    #print stuff
    parser.add_argument('--main-print', type=str, default=file_main_print, help='This option removes the main print from the system. The default is no. In case of any problems executing this code, the main printing can be activated, and in case any problem still persists you can activate more printing options in the \'memory_all.py\' file.')

    parser.add_argument('--kill-print', type=str, default=file_kill_print, help='This option removes the signal kill print from the system and online protocols information. The default is no. Adding this option the honeypot will print PID, -USR1, -USR2 options and online protocols')

    parser.add_argument('--main-all-prints', type=str, default=file_main_all_prints, help='This option removes all basic print functions from the system (tcpdump, [*Loop] [protocol] address/ports ). The default is yes.')

    parser.add_argument('--warning-print', type=str, default=file_warning_print, help='This option removes all warnings messagens print in the system. The default is yes.')

    #memcached
    parser.add_argument('--memcached-bind-ip', type=str, default=file_memcached_bind_ip, help='Address the server should bind to. The default is 127.0.0.1.')

    parser.add_argument('--memcached-bind-port', type=int, default=file_memcached_bind_port, help='Port the server should bind to. The default is 11000. The official port use by memcached is 11211, if you can change the default port of --memcached-bind-port-server to another port (remember that --memcached-bind-port-server port will be use to make request to a official server/service), than you can use 11211 here. (this is the port that will be use by the honeypot)')

    parser.add_argument('--memcached-bind-ip-server', type=str, default=file_memcached_bind_ip_server, help='Address the server should bind to. The default is 127.0.0.1.')

    parser.add_argument('--memcached-bind-port-server', type=int, default=file_memcached_bind_port_server, help='Port the server should bind to. The default is 11211')

    parser.add_argument('--memcached-run', type=str, default=file_memcached_run, help='This option prevents that honey-memcached run. The default is yes.')

    #tcpdump
    parser.add_argument('--tcpdump-run', type=str, default=file_tcpdump_run, help='This option prevents that TCPDUMP run. [Warning do not change this option] [The default is yes]\n**In case of this option be change for \'no\', the traffic capture will not happen.')

    #dns
    parser.add_argument('--dns_bind-ip', type=str, default=file_dns_bind_ip, help='Address the server should bind to.  The default is 127.0.0.1.')

    parser.add_argument('--dns_bind-port', type=int, default=file_dns_bind_port, help='Port the server should bind to. The default is 53. (this is the port that will be use by the honeypot)')

    parser.add_argument('--unbound-ip', type=str, default=file_unbound_bind_ip, help='Address of the DNS server that should be queried.  The default is 8.8.8.8.')

    parser.add_argument('--unbound-port', type=int, default=file_unbound_bind_port, help='Port of the DNS server that should be queried. The default in some machines are 53 the correct approach is change for another port, this way the --dns_bind-port can use the "real port".(TIP: other port that can be use is 53000, this port is the port for the unbound server)')

    parser.add_argument('--dns-run', type=str, default=file_dns_run, help='This option prevents that honey-dns run. The default is yes.')

    #ntp config
    parser.add_argument('--ntp-bind-ip', type=str, default=file_ntp_bind_ip, help='Address the server should bind to. The default is 127.0.0.1.')

    parser.add_argument('--ntp-bind-port', type=int, default=file_ntp_bind_port, help='Port the server should bind to. The default is 123. (TIP: is not a good ideia to change this port, because the basic tools that you can use to check the system, like ntpd, ntpdc and ntpq don\'t give a user the option to change the port)')

    parser.add_argument('--ntp-run', type=str, default=file_ntp_run, help='This option prevents that honey-ntp run. The default is yes.')

    #ssdp config
    parser.add_argument('--ssdp-bind-ip', type=str, default=file_ssdp_bind_ip, help='Address the server should bind to. The default is 127.0.0.1.')

    parser.add_argument('--ssdp-bind-port', type=int, default=file_ssdp_bind_port, help='Port the server should bind to. The default is 1900.')

    parser.add_argument('--ssdp-run', type=str, default=file_ssdp_run, help='This option prevents that honey-ssdp run. The default is yes.')

    #coap config
    parser.add_argument('--coap-bind-ip', type=str, default=file_coap_bind_ip, help='Address the server should bind to. The default is 127.0.0.1.')

    parser.add_argument('--coap-bind-port', type=int, default=file_coap_bind_port, help='Port the server should bind to. The default is 5683.')

    parser.add_argument('--coap-run', type=str, default=file_coap_run, help='This option prevents that honey-coap run. The default is yes.')

    #cldap config
    parser.add_argument('--cldap-bind-ip', type=str, default=file_cldap_bind_ip, help='Address the server should bind to. The default is 127.0.0.1.')

    parser.add_argument('--cldap-bind-port', type=int, default=file_cldap_bind_port, help='Port the server should bind to. The default is 389.')

    parser.add_argument('--cldap-run', type=str, default=file_cldap_run, help='This option prevents that honey-cldap run. The default is yes.')

    #syslog
    parser.add_argument('--syslog-level', type=str, default=file_syslog, help='This option define the syslog level. The default is ERROR and is define on config_honeypot.ini file.')

    #get args
    args = parser.parse_args()

    kwargs = {
        'print_loadbar': args.print_loadbar,
        'chargen_bind_address': args.chargen_bind_ip,
        'chargen_bind_port': args.chargen_bind_port,
        'chargen_run' : args.chargen_run,
        'qotd_bind_address': args.qotd_bind_ip,
        'qotd_bind_port': args.qotd_bind_port,
        'qotd_path': args.qotd_path,
        'qotd_run' : args.qotd_run,
        'steam_bind_address': args.steam_bind_ip,
        'steam_run': args.steam_run,
        'main_print': args.main_print,
        'kill_print': args.kill_print,
        'main_all_prints': args.main_all_prints,
        'warning_print': args.warning_print,
        'memcached_bind_address': args.memcached_bind_ip,
        'memcached_bind_port': args.memcached_bind_port,
        'memcached_bind_ip_server': args.memcached_bind_ip_server,
        'memcached_bind_port_server': args.memcached_bind_port_server,
        'memcached_run': args.memcached_run,
        'tcpdump_run': args.tcpdump_run,
        'dns_bind_address': args.dns_bind_ip,
        'dns_bind_port': args.dns_bind_port,
        'unbound_server': args.unbound_ip,
        'unbound_port': args.unbound_port,
        'dns_run': args.dns_run,
        'ntp_bind_address': args.ntp_bind_ip,
        'ntp_bind_port': args.ntp_bind_port,
        'ntp_run': args.ntp_run,
        'ssdp_bind_address': args.ssdp_bind_ip,
        'ssdp_bind_port': args.ssdp_bind_port,
        'ssdp_run': args.ssdp_run,
        'coap_bind_address': args.coap_bind_ip,
        'coap_bind_port': args.coap_bind_port,
        'coap_run' : args.coap_run,
        'cldap_bind_address': args.cldap_bind_ip,
        'cldap_bind_port': args.cldap_bind_port,
        'cldap_run' : args.cldap_run,
        'syslog_level': args.syslog_level
    }

    try:

        worker = Main_honey(**kwargs)
        worker.run()

    except OSError:
        print('[main_all parser function] \n [Error 98] Address already in use [main_all]')

    except KeyboardInterrupt as e:
        print('Exit using ctrl^C')

    except Exception as e:
        print('[Main_all parser function]',e)

    finally:
        if(Memory_all.flag_print == True):
            print('[*RUN...]')
