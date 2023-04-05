import argparse

from sys import exit
from typing import Union
from redis.exceptions import ConnectionError

#requests 
from requests import post
from requests.exceptions import ConnectionError as RedisConnectionError

from time import time

#socket dns & reverse dns (TODO:perform mx parsing)
from socket import getfqdn,gethostbyname

#scapy layers
from scapy.layers.inet import fragment
# TODO:from scapy.layers.http import HTTPRequest

from scapy.all import Ether as ether
from scapy.all import Packet,Raw,ARP,ICMP,DNSQR,TCP,IP,UDP,DHCP,sniff,srp,get_if_addr

#Object Serialization
from pydantic import BaseModel

# IP Distante
LOG_SERVER_URL    = 'http://localhost:8080/rlog'

# Filtres bruts IP & PORTS
blacklist_ips     : set[str] = ["44.32.214.17"]
blacklist_mac     : set[str] = ["00:00:00:00:00:00"]
# TODO: blacklist_domains : set[str] = ["perdu.com"]
blacklist_ports   : set[int] = [1234,4321,6666]

#Log serializer
class Log(BaseModel):
    class Config:
        arbitrary_types_allowed = True

    timestamp : float                 #packet timestamp
    pkt       : str                   #packet body
    info      : Union[None,dict] #packet flags and junk details

######### UTILS

# Awnser a device from his ARP address directly from his table
def mac(ip) -> str:
    try:
        arp_request = ARP(pdst=ip) #forge ARP req
        distant_mac = srp(ether(dst="ff:ff:ff:ff:ff:ff") / arp_request, timeout=5, verbose=False)[0] #send it
        return distant_mac[0][1].hwsrc

    except:
        return ""
    
# Try to resolve domain name
def resolve_domain(hostname:str) -> str:
    return getfqdn(hostname)

# Try to resolve ip from domain name
def resolve_ip(hostname:str) -> str:
    return gethostbyname(hostname)
######### END UTILS


######## SCAPY PARSER

#########
# Sending json logs to middleware_logger.py every 64 packets logged by Scapy
# void send_logs(Log new_log) {}
# Log new_log => New log to add to stack
#########
def send_logs(new_log : Log) -> None:
    #If stack size less than stack_size arg, 64 by default
    if (len(logs_stack) < args.stack_size):
        logs_stack.append(new_log.json())

    #Else try to send logs to server
    else:
        try:
            response = post(LOG_SERVER_URL, json={"logs_stack":logs_stack})

            #let the stack grow while server unreachable
            if (response.status_code != 200):
                print("Error while trying to join server -> saving packet to stack\n")
                logs_stack.append(new_log.json())
                pass
            
            #if the server have respond then clear stack
            else: logs_stack.clear()

        except KeyboardInterrupt:
            exit(1)

        except ConnectionError or RedisConnectionError:
            print("Error while trying to join server, I will retry\n")
            pass
    
        except Exception as e:
            print("ERROR MUST BE EXCEPTED AND HANDLED => %s"%e)
            logs_stack.append(new_log.json())
            pass

#########
# Filtering every packets from personnal filters
# Log filter(Packet pkt) {return Log();}
# scapy.Packet pkt -> the packet to filter
#########
def filter(pkt : Packet) -> Log:
    details : list[str] = []
    log     : Log       = Log(timestamp=time(),pkt=str(pkt.show(dump=True)),info={"category":"info","flags":details})

    #IP layer check
    if pkt.haslayer(IP):
        # Extract packet fields
        ihl = pkt[IP].ihl
        tot_len = pkt[IP].len
        flags = pkt[IP].flags
        frag_offset = pkt[IP].frag
        ttl = pkt[IP].ttl
        # version = pkt[IP].version
        # tos = packet[IP].tos
        # id = packet[IP].id
        # protocol = packet[IP].proto
        # check = pkt[IP].chksum
        # src = packet[IP].src
        # dst = packet[IP].dst

        if (len(pkt[IP]) > 65535):
            details.append("Exceeded ip length")
        
        if (tot_len != len(pkt[IP])):
            details.append("Invalid IP packet length")

        # Check if ihl's valid
        if (ihl < 5):
            details.append("Invalid IP packet: IHL is too small")

        # Check if ttl's valid
        if (ttl == 0):
            details.append("Invalid IP packet: TTL is zero")

        # Check packet's fragmentation status
        if (flags == 0x1):
            # Ectract packet's fragments
            fragments = fragment(pkt)

            # Check if fragments are correctly ordoned
            if all(frag_offset == i*8 for i in range(len(fragments))):
                # Check if fragments are overlapping
                for i in range(len(fragments)-1):
                    if fragments[i].payload[-8:] != fragments[i+1].payload[:8]:
                        details.append("Fragments doesn't overlap correctly")

            else:
                details.append("Fragments unordered")

        # Validate checksum as we recalculate it
        if (pkt.chksum != pkt.__class__(bytes(pkt)).chksum):
            details.append("Invalid checksum")

    #blacklist ip
    if (IP in pkt):
        if (resolve_ip(pkt[IP].src) in blacklist_ips or resolve_ip(pkt[IP].dst) in blacklist_ips):
            details.append("Blacklisted ip")
        # if ((pkt[IP].dst) != "192.168.1.1" and pkt[IP].dst != my_ip):
        #     print(pkt[IP].dst)
        # if (resolve_domain(pkt[IP].src) in blacklist_domains):
        #     details.append("Blacklisted domain")

    #blacklist port
    if (TCP in pkt 
        and (pkt[TCP].sport in blacklist_ports or pkt[TCP].dport in blacklist_ports)):
            details.append("Blacklisted port")

    # blacklist mac
    if (ether in pkt 
        and pkt[ether].src in blacklist_mac or pkt[ether].dst in blacklist_mac):
            details.append("Blacklisted mac")


    #Bruteforce Auth (TODO:Enforce)
    if (TCP in pkt and "authentication failed" in str(pkt[TCP].payload).lower()):
        details.append("Bruteforce attempt")
        # Ajouter ici le code pour bloquer l'adresse IP source ou déclencher une alerte

    #DDoS
    if (IP in pkt and pkt[IP].ttl >= 255):
        details.append("Mostly ddos")
    
    try:
        #ARP -> TODO:BUG
        if (ARP in pkt 
            and (pkt[ARP].hwsrc != pkt[ARP].hwdst and pkt[ARP].op == 1)
            or (mac(pkt[ARP].psrc) != pkt[ARP].hwsrc)):
            details.append("ARP poisoning")

    except:
        pass

    #ICMP
    if (ICMP in pkt and (len(pkt[ICMP]) > 65535)):
        details.append("Ping of death")
    
    # if(ICMP in pkt and pkt.lastlayer() != "Raw"):
    #     if ((pkt.lastlayer().payload[0] == 8 or pkt.lastlayer().payload[0] == 0) and pkt.lastlayer().payload[1] == 0):
    #         details.append("Icmp flood")

    #DHCP
    if (DHCP in pkt and pkt[DHCP].options[0][1] == 3):
        details.append("DHCP snooping")

    # #DNS TODO:BUG false-positive
    # if (DNSQR in pkt
    #       and pkt[DNSQR].qtype == 1 and pkt[DNSQR].qclass == 1):
    #     details.append("DNS amplification")

    #SQL (TODO:Enforce & Add Redis filters)
    if pkt.haslayer(Raw):
        load = pkt[Raw].load.decode('utf-8', 'ignore')
        if any(sql in load for sql in ["SELECT", "UPDATE", "DELETE", "INSERT", "EXEC"]):
            details.append("SQL sudo commands from outside")

    #Redis
    if pkt.haslayer(Raw):
        load = pkt[Raw].load.decode('utf-8', 'ignore')
        if "redis" in load.lower():
            print("Redis Sniffing Attack detected from {}".format(pkt[IP].src))



    #if we have junk traffic then update log's info with details
    if (len(details) >= 1):
        log.info = {"category":"WARN","flags":details}
    else: #else log's info is None
        log.info = None

    return log


def packet_capture(pkt):
    # Filter packet using filter() func
    log_filtered : Log = filter(pkt=pkt)

    # if junk traffic send_logs
    if (log_filtered.info != None):
        send_logs(log_filtered)
    
    # log all traffic (noisy)
    # send_logs(log_filtered)

if __name__ == "__main__":
    try:
        # Arguments parser
        parser = argparse.ArgumentParser(prog='pynetlog',description='Simple network logger using Scapy',epilog='0xanalog')
        parser.add_argument('-i','--iface',dest="iface",required=True,help='Network interface (wlan0,eth0,eno0,wlp2s0) to sniff')
        parser.add_argument('-n','--send-rate',dest="stack_size",type=int,required=False,default=64,help='After how many logged packets send data to server (default=64)?')
        args = parser.parse_args()

        logs_stack : list[dict] = [] #packet's stack send if (i_log == stack_size)

        # Knowing self-ip for later
        my_ip : str = get_if_addr(args.iface)

        # Starting packets capture
        sniff(prn=packet_capture,store=False,iface=args.iface)


    # except ConnectionError:
    #     print("Erreur lors de l\'envoi des logs au serveur distant\n")
    #     exit(1)

    except KeyboardInterrupt:
        print("BYE\n")
        exit(1)

    except PermissionError:
        print("Script must be run as root or in an environment providing an access to your network's interface :(")
        exit(1)

    except Exception as e:
        raise e
