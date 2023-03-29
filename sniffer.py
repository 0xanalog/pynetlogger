import argparse
import gzip

from sys import exit
from typing import Union

#requests 
from requests import post
from requests.exceptions import ConnectionError

from time import time

#socket dns & reverse dns (TODO:perform mx parsing)
from socket import getfqdn,gethostbyname

#scapy layers
from scapy.layers.inet import fragment
# TODO:from scapy.layers.http import HTTPRequest

from scapy.all import Ether as ether
from scapy.all import Packet,Raw,ARP,ICMP,DNSQR,TCP,IP,UDP,DHCP,sniff,srp,wrpcap,checksum

#Object Serialization
from pydantic import BaseModel

# IP Distante
LOG_SERVER_URL    = 'http://localhost:8080/rlog'

# Filtres bruts IP & PORTS
blacklist_ips     : set[str] = ["44.32.214.17"]
blacklist_mac     : set[str] = ["00:00:00:00:00:00"]
blacklist_domains : set[str] = ["perdu.com"]
blacklist_ports   : set[int] = [1234,4321,6666]

class Log(BaseModel):
    class Config:
        arbitrary_types_allowed = True

    timestamp : float
    pkt       : str
    info      : dict

# i_log     : int       = 0  #log counter
logs_stack : list[str] = [] #temp packet's stack send if (i_log == 64)

def remove_float_to_int(timestamp:float) -> int:
    return int(str(timestamp).replace(".", ""))

# Fonction d'envoi des logs JSON au serveur distant (middleware_logger)
def send_logs(new_log : Log):
    log_id : int = remove_float_to_int(new_log.timestamp)

    if (len(logs_stack) < 64):
        #print(new_log.timestamp)
        logs_stack.append(new_log.json())

    else:
        #tentative d'envoi des logs au serveur
        try:
            # print([type(logs_stack),logs_stack])
            response = post(LOG_SERVER_URL, json={"logs_stack":logs_stack})

            #laisser augmenter la stack de packets en attendant de pouvoir joindre le serveur
            if (response.status_code != 200):
                print("Erreur lors de l\'envoi des logs au serveur distant -> sauvegarde stack\n")
                logs_stack.append(new_log.json())
                pass

            else:
                logs_stack.clear()

        except Exception as e:
            print(e)
            logs_stack.append(new_log.json())
            pass

# Questionner un device et recuperer sa MAC
def mac(ip) -> str:
    try:
        arp_request = ARP(pdst=ip) #forge ARP req
        distant_mac = srp(ether(dst="ff:ff:ff:ff:ff:ff") / arp_request, timeout=5, verbose=False)[0] #send it
        return distant_mac[0][1].hwsrc

    except:
        return ""
    
# tenter de resoudre les noms de domaines
def resolve_domain(hostname:str) -> str:
    return getfqdn(hostname)

# Resoudre une IP depuis son domaine
def resolve_ip(hostname:str) -> str:
    return gethostbyname(hostname)


# Le traffic est-il malicieux ?
def filter(pkt : Packet) -> Union[None,Log]:
    details : list[str] = []
    log     : Log       = Log(timestamp=time(),pkt=str(pkt),info={"category":"info","details":details})

    #IP layer check
    if pkt.haslayer(IP):
        # Extraire les champs du paquet
        version = pkt[IP].version
        ihl = pkt[IP].ihl
        tot_len = pkt[IP].len
        flags = pkt[IP].flags
        frag_offset = pkt[IP].frag
        ttl = pkt[IP].ttl
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

        # Vérifier si IHL est valide
        if ihl < 5:
            details.append("Invalid IP packet: IHL is too small")

        # Vérifier si le champ TTL est valide
        if ttl == 0:
            details.append("Invalid IP packet: TTL is zero")

        # Vérifier si le paquet est fragmenté
        if flags == 0x1:
            # Extraire les fragments du paquet
            fragments = fragment(pkt)

            # Vérifier si les fragments sont correctement ordonnés
            if all(frag_offset == i*8 for i in range(len(fragments))):
                # Vérifier si les fragments se chevauchent correctement
                for i in range(len(fragments)-1):
                    if fragments[i].payload[-8:] != fragments[i+1].payload[:8]:
                        details.append("Fragments doesn't overlap correctly")

            else:
                details.append("Fragments unordered")

        # Vérifier la validité du checksum
        if (pkt.chksum != pkt.__class__(bytes(pkt)).chksum):
            details.append("Invalid checksum")

    #blacklist ip
    if (IP in pkt):
        if (resolve_ip(pkt[IP].src) in blacklist_ips or resolve_ip(pkt[IP].dst) in blacklist_ips):
            details.append("Blacklisted ip")
        if (resolve_domain(pkt[IP].src) in blacklist_domains):
            details.append("Blacklisted domain")

    #blacklist port
    if (TCP in pkt 
        and (pkt[TCP].sport in blacklist_ports or pkt[TCP].dport in blacklist_ports)):
            details.append("Blacklisted port")

    # blacklist mac
    if (ether in pkt 
        and pkt[ether].src in blacklist_mac or pkt[ether].dst in blacklist_mac):
            details.append("Blacklisted mac")


    #Bruteforce Auth
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
    
    if(ICMP in pkt and pkt.lastlayer() != "Raw"):
        if ((pkt.lastlayer().payload[0] == 8 or pkt.lastlayer().payload[0] == 0) and pkt.lastlayer().payload[1] == 0):
            details.append("Icmp flood")
    
    #SYN
    if (TCP in pkt and (pkt[TCP].flags == "S")): 
        details.append("Syn flood")

    #DHCP
    if (DHCP in pkt and pkt[DHCP].options[0][1] == 3):
        details.append("DHCP snooping")

    #DNS
    if (DNSQR in pkt
          and pkt[DNSQR].qtype == 1 and pkt[DNSQR].qclass == 1):
        details.append("DNS amplification")

    #SQL
    if (Raw in pkt and pkt.dport == 3306 
          and ("SELECT" or "DROP" or "GET" in str(pkt[Raw].load))):
        details.append("SQL access from outside")



    if (len(details) >= 1): #si on a un traffic malveillant
        log.info = {"category":"WARN","details":details}
        return log

    return None


def packet_capture(pkt):
    # Enregistrer le paquet dans le fichier pcapng
    wrpcap('packets.pcapng', pkt, append=True)

    log_analyzed : Union[None,Log] = filter(pkt=pkt)

    if (log_analyzed != None):
        # Envoyer le log JSON au serveur distant si il contient du traffic suspect
        send_logs(log_analyzed)

    # if (len(is_malicious["info"]["details"]) >= 1): #Si est suspect, on drop en affichant le log
    #     print(is_malicious["info"])

if __name__ == "__main__":
    try:
        # Arguments parser
        parser = argparse.ArgumentParser(prog='pynetlog',description='Simple network logger using Scapy',epilog='0xanalog')
        parser.add_argument('-i','--iface',dest="iface",required=True)
        args = parser.parse_args()

        # Démarrer la capture de paquets
        sniff(prn=packet_capture,store=False,iface=args.iface)


    except ConnectionError:
        print("Erreur lors de l\'envoi des logs au serveur distant\n")
        exit(1)

    except KeyboardInterrupt:
        print("BYE\n")
        exit(1)

    except PermissionError:
        print("Le script doit etre lance en root (utilisez sudo ou un environnement ayant les droits d'ecoute sur l'interface reseau de votre machine)")
        exit(1)

    except Exception as e:
        raise e
