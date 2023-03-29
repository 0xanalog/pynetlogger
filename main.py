import gzip
import json
import sys
import requests
import time
import socket

from scapy.all import Ether as ether
from scapy.all import Packet,Raw,ARP,DNS,ICMP,DNSQR,TCP,IP,UDP,DHCP,sniff,srp,wrpcap

from pydantic import BaseModel

# IP Distante
LOG_SERVER_URL  = 'http://192.168.1.21:8080/logs'

# Filtres bruts IP & PORTS
blacklist_ips     = ["44.32.214.17"]
blacklist_mac     = ["00:00:00:00:00:00"]
blacklist_domains = ["perdu.com"]
blacklist_ports   = [1234,4321,6666]

class Log(BaseModel):
    class Config:
        arbitrary_types_allowed = True

    timestamp : float
    pkt       : Packet
    info      : dict


# Fonction d'envoi des logs JSON au serveur distant
def send_logs(log : dict):
    response = requests.post(LOG_SERVER_URL, data=log)
    if response.status_code != 200:
        print("Erreur lors de l\'envoi des logs au serveur distant")


# Questionner un device et recuperer sa MAC
def mac(ip) -> str:
    try:
        arp_request = ARP(pdst=ip) #forge ARP req
        distant_mac = srp(ether(dst="ff:ff:ff:ff:ff:ff") / arp_request, timeout=5, verbose=False)[0] #send it
        # print(type(distant_mac[0][1].hwsrc))
        return distant_mac[0][1].hwsrc

    except:
        return ""
    
# tenter de resoudre les noms de domaines
def resolve_domain(hostname:str) -> str:
    return socket.getfqdn(hostname)

# Resoudre une IP depuis son domaine
def resolve_ip(hostname:str) -> str:
    return socket.gethostbyname(hostname)


# Le traffic est-il malicieux ?
def filter(pkt : Packet) -> dict[str,str]:
    details : list[str] = []
    log     : Log       = Log(timestamp=time.time(),pkt=pkt,info={"category":"info","details":details})
    

    #IP length
    if (IP in log.pkt and len(pkt) > 65535):
        details.append("exceeded ip length")


    #blacklist ip
    if (IP in log.pkt):
        if (resolve_ip(log.pkt[IP].src) in blacklist_ips or resolve_ip(log.pkt[IP].dst) in blacklist_ips):
            details.append("blacklisted ip")
        if (resolve_domain(log.pkt[IP].src) in blacklist_domains):
            details.append("blacklisted domain")

    #blacklist port
    if (TCP in log.pkt 
        and (log.pkt[TCP].sport in blacklist_ports or log.pkt[TCP].dport in blacklist_ports)):
            details.append("blacklisted port")

    # blacklist mac
    if (ether in log.pkt 
        and log.pkt[ether].src in blacklist_mac or log.pkt[ether].dst in blacklist_mac):
            details.append("blacklisted mac")


    #Bruteforce Auth
    if (TCP in log.pkt and "authentication failed" in str(log.pkt[TCP].payload).lower()):
        details.append("bruteforce attempt")
        # Ajouter ici le code pour bloquer l'adresse IP source ou déclencher une alerte

    #DDoS
    if (IP in pkt and pkt[IP].ttl <= 200):
        details.append("mostly ddos")

    #ARP
    if ((ARP in log.pkt and log.pkt[ARP].op == 2) 
        and (mac(log.pkt[ARP].psrc) != log.pkt[ARP].hwsrc)):
        details.append("arp poisoning")

    #ICMP
    if (ICMP in log.pkt and (len(log.pkt[ICMP]) > 65535)):
        details.append("ping of death")
    
    if(ICMP in log.pkt and log.pkt.lastlayer() != "Raw"):
        if ((log.pkt.lastlayer().payload[0] == 8 or log.pkt.lastlayer().payload[0] == 0) and log.pkt.lastlayer().payload[1] == 0):
            details.append("icmp flood")
    
    #SYN
    if (TCP in log.pkt and (log.pkt[TCP].flags == "S")): 
        details.append("syn flood")

    #DHCP
    if (DHCP in log.pkt and log.pkt[DHCP].options[0][1] == 3):
        details.append("DHCP snooping")

    #DNS
    if (DNSQR in log.pkt
          and log.pkt[DNSQR].qtype == 1 and log.pkt[DNSQR].qclass == 1):
        details.append("dns amplification")


    #SQL
    if (Raw in log.pkt and log.pkt.dport == 3306 
          and ("SELECT" or "DROP" or "GET" in str(log.pkt[Raw].load))):
        details.append("sqli")

    if (len(details) >= 1): #si on a un traffic malveillant
        log.info = {"category":"WARN","details":details}
    else:
        log.info = {"category":"info","details":[]}

    return log.dict()



def packet_capture(pkt):
    # Enregistrer le paquet dans le fichier pcapng
    wrpcap('packets.pcapng', pkt, append=True)

    is_malicious : dict = filter(pkt=pkt)

    # JSON correspondant au paquet capturé
    log = {
        'timestamp': time.time(),
        'packet': str(pkt),
        'info':is_malicious
    }
    # Envoyer le log JSON au serveur distant
    send_logs(log)

    # if (len(is_malicious["info"]["details"]) >= 1): #Si est suspect, on drop en affichant le log
    #     print(is_malicious["info"])

if __name__ == "__main__":
    try:
        # Démarrer la capture de paquets
        sniff(prn=packet_capture,store=False)

        # Compresser le fichier pcapng de sortie avec gzip
        with open('packets.pcapng', 'rb') as f_in:
            with gzip.open('packets.pcapng.gz', 'wb') as f_out:
                f_out.writelines(f_in)


    except requests.exceptions.ConnectionError:
        print("Erreur lors de l\'envoi des logs au serveur distant\n")
        sys.exit(1)

    except KeyboardInterrupt:
        print("BYE\n")
        sys.exit(1)

    except PermissionError:
        print("Le script doit etre lance en root (utilisez sudo ou un environnement ayant les droits d'ecoute sur l'interface reseau de votre machine)")
        sys.exit(1)

    except Exception as e:
        raise e
