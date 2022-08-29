all:
		python3 main_all.py

h:
		python3 main_all.py -hs
-h:
		python3 main_all.py -h
help:
		python main_all.py -h

run:
		python3 main_all.py --steam-run yes

install_pip:
		sudo pip3 install -r requirements.txt

clean_sqlite:
		rm -rf database/*.sqlite

clean_tcpdump:
		rm -rf tcpdump/pcap_file/tcpdump*

clean:
		rm -rf __pycache__ chargen/__pycache__ tcpdump_/__pycache__ qotd/__pycache__  chargen/*.sqlite *.sqlite qotd/*.sqlite steam_/*.sqlite steam_/__pycache__ memcached_/__pycache__ dns_/__pycache__ ntp_/__pycache__ ssdp_/__pycache__ config_file/__pycache__/  syslog_/__pycache__/ others/__pycache__/
		#make clean_sqlite
