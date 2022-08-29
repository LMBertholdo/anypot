FROM python:3.8

COPY iptables/ iptables/
COPY main/ mph/
WORKDIR mph/

RUN pip3 install -r requirements.txt
RUN apt update && apt install -y netcat tcpdump sqlite3 python3-dateutil libcap-dev iptables

EXPOSE 53/udp
EXPOSE 11211/udp
EXPOSE 123/udp
EXPOSE 19/udp
EXPOSE 17/udp
EXPOSE 27015/udp
EXPOSE 27015/tcp
EXPOSE 1900/udp
EXPOSE 5683/udp
EXPOSE 389/udp

ENTRYPOINT ["./startup.sh"]
