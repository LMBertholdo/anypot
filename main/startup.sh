#!/bin/sh
IP=${IP:-$(hostname -I)}

LO=${1:-lo}
INTERFACE=${3:-eth0}

CHARGEN_BIND_IP=${CHARGEN_BIND_IP:-$IP}
QOTD_BIND_IP=${QOTD_BIND_IP:-$IP}
STEAM_BIND_IP=${STEAM_BIND_IP:-$IP}
MEMCACHED_BIND_IP=${MEMCACHED_BIND_IP:-$IP}
MEMCACHED_BIND_IP_SERVER=${MEMCACHED_BIND_IP_SERVER:-$IP}
DNS_BIND_IP=${DNS_BIND_IP:-$IP}
UNBOUND_IP=${UNBOUND_IP:-$IP}
NTP_BIND_IP=${NTP_BIND_IP:-$IP}
SSDP_BIND_IP=${SSDP_BIND_IP:-$IP}
COAP_BIND_IP=${COAP_BIND_IP:-$IP}
CLDAP_BIND_IP=${CLDAP_BIND_IP:-$IP}

CHARGEN_BIND_PORT=${CHARGEN_BIND_PORT:-"53019"}
QOTD_BIND_PORT=${QOTD_BIND_PORT:-"53017"}
MEMCACHED_BIND_PORT=${MEMCACHED_BIND_PORT:-"11211"}
MEMCACHED_BIND_PORT_SERVER=${MEMCACHED_BIND_PORT_SERVER:-"11111"}
DNS_BIND_PORT=${DNS_BIND_PORT:-"53000"}
UNBOUND_PORT=${UNBOUND_PORT:-"53"}
NTP_BIND_PORT=${NTP_BIND_PORT:-"53123"}
SSDP_BIND_PORT=${SSDP_BIND_PORT:-"1900"}
COAP_BIND_PORT=${COAP_BIND_PORT:-"5683"}
CLDAP_BIND_PORT=${CLDAP_BIND_PORT:-"38900"}

CHARGEN_RUN=${CHARGEN_RUN:-"yes"}
QOTD_RUN=${QOTD_RUN:-"yes"}
STEAM_RUN=${STEAM_RUN:-"yes"}
MEMCACHED_RUN=${MEMCACHED_RUN:-"no"}
DNS_RUN=${DNS_RUN:-"yes"}
NTP_RUN=${NTP_RUN:-"yes"}
SSDP_RUN=${SSDP_RUN:-"yes"}
COAP_RUN=${COAP_RUN:-"yes"}
CLDAP_RUN=${CLDAP_RUN:-"yes"}

QOTD_PATH=${QOTD_PATH:-"./qotd/jokes.txt"}

PRINT_LOADBAR=${PRINT_LOADBAR:-"True"}
MAIN_PRINT=${MAIN_PRINT:-"no"}
KILL_PRINT=${KILL_PRINT:-"yes"}
MAIN_ALL_PRINTS=${MAIN_ALL_PRINTS:-"yes"}
WARNING_PRINT=${WARNING_PRINT:-"yes"}
TCPDUMP_RUN=${TCPDUMP_RUN:-"no"}
SYSLOG_LEVEL=${SYSLOG_LEVEL:-"ERROR"}

cd /iptables
cat iptables/iptables-rules.new | sed 's/lo /'"$LO"' /g' | sed 's/ens3/'"$INTERFACE"'/g'>> firewall.new
echo y | iptables-apply firewall.new
echo y | ip6tables-apply iptables/ip6tables-rules.new

cd /mph
python3 main_all.py \
--print-loadbar $PRINT_LOADBAR \
--chargen-bind-ip $CHARGEN_BIND_IP \
--chargen-bind-port $CHARGEN_BIND_PORT \
--chargen-run $CHARGEN_RUN \
--qotd-bind-ip $QOTD_BIND_IP \
--qotd-bind-port $QOTD_BIND_PORT \
--qotd-path $QOTD_PATH \
--qotd-run $QOTD_RUN \
--steam-bind-ip $STEAM_BIND_IP \
--steam-run $STEAM_RUN \
--main-print $MAIN_PRINT \
--kill-print $KILL_PRINT \
--main-all-prints $MAIN_ALL_PRINTS \
--warning-print $WARNING_PRINT \
--memcached-bind-ip $MEMCACHED_BIND_IP \
--memcached-bind-port $MEMCACHED_BIND_PORT \
--memcached-bind-ip-server $MEMCACHED_BIND_IP_SERVER \
--memcached-bind-port-server $MEMCACHED_BIND_PORT_SERVER \
--memcached-run $MEMCACHED_RUN \
--tcpdump-run $TCPDUMP_RUN \
--dns_bind-ip $DNS_BIND_IP \
--dns_bind-port $DNS_BIND_PORT \
--unbound-ip $UNBOUND_IP \
--unbound-port $UNBOUND_PORT \
--dns-run $DNS_RUN \
--ntp-bind-ip $NTP_BIND_IP \
--ntp-bind-port $NTP_BIND_PORT \
--ntp-run $NTP_RUN \
--ssdp-bind-ip $SSDP_BIND_IP \
--ssdp-bind-port $SSDP_BIND_PORT \
--ssdp-run $SSDP_RUN \
--coap-bind-ip $COAP_BIND_IP \
--coap-bind-port $COAP_BIND_PORT \
--coap-run $COAP_RUN \
--cldap-bind-ip $CLDAP_BIND_IP \
--cldap-bind-port $CLDAP_BIND_PORT \
--cldap-run $CLDAP_RUN \
--syslog-level $SYSLOG_LEVEL \
> logs/mph_$(date +"%Y-%m-%dT%H:%M:%S").log
