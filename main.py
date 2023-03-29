import gzip
import json
import requests
import time
from scapy.all import Ether as ether
from scapy.all import Packet,Raw,ARP,DNS,ICMP,DNSQR,TCP,IP,sniff,srp,wrpcap

from pydantic import BaseModel

# IP Distante
LOG_SERVER_URL  = 'http://192.168.1.21:8080/logs'

# Filtres bruts IP & PORTS
malicious_ips   = ["44.32.214.17","google.fr"]
malicious_ports = [1234,4321,6666]

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
        print('Erreur lors de l\'envoi des logs au serveur distant')


# Questionner un device et recuperer sa MAC
def mac(ip) -> str:
    try:
        arp_request = ARP(pdst=ip) #forge ARP req
        distant_mac = srp(ether(dst="ff:ff:ff:ff:ff:ff") / arp_request, timeout=5, verbose=False)[0] #send it
        # print(type(distant_mac[0][1].hwsrc))
        return distant_mac[0][1].hwsrc

    except:
        return ""

# Le traffic est-il malicieux ?
def filter(pkt : Packet) -> dict[str,str]:
    details : list[str] = [""]
    log     : Log       = Log(timestamp=time.time(),pkt=pkt,info={"category":"info","details":details})
    

    #len check
    if (len(pkt) > 65535):
        details.append("exceeded ip length")

    #blacklist check
    if (log.pkt.haslayer(IP) and log.pkt.haslayer(TCP) 
        and ((log.pkt[IP].src in malicious_ips or log.pkt[IP].dst in malicious_ips) 
        or (log.pkt[TCP].sport in malicious_ports or log.pkt[TCP].dport in malicious_ports))):
        details.append("blacklisted access")

    #ARP
    if log.pkt.haslayer(ARP) and log.pkt[ARP].op == 2:
        true_mac = mac(log.pkt[ARP].psrc)
        req_mac  = log.pkt[ARP].hwsrc
    
        if (true_mac != req_mac):
            details.append("arp poisoning")

    #ICMP
    if (log.pkt.haslayer(ICMP) and (len(log.pkt[ICMP]) > 65535)):
        details.append("ping of death")
    
    if(log.pkt.haslayer(ICMP) and log.pkt.lastlayer() != "Raw"):
        if ((log.pkt.lastlayer()[0] == 8 or log.pkt.lastlayer()[0] == 0) and log.pkt.lastlayer()[1] == 0):
            details.append("icmp flood")
    
    #SYN
    if (log.pkt.haslayer(TCP) and (log.pkt[TCP].flags == "S")): 
        details.append("syn flood")

    # if(log.pkt.haslayer(TCP) 
    #    and (log.pkt.lastlayer().op == 2)):
    #     details.append("malicious tcp")

    #DNS
    if (log.pkt.haslayer(DNSQR) 
          and log.pkt[DNSQR].qtype == 1 and log.pkt[DNSQR].qclass == 1):
        details.append("dns amplification")


    #SQL
    if (log.pkt.haslayer(Raw) and log.pkt.dport == 3306 
          and ("SELECT" or "DROP" or "GET" in str(log.pkt[Raw].load))):
        details.append("sqli")

    if (len(details) > 1): #si on a un traffic malveillant
        log.info = {"category":"WARN","details":details}
    else:
        log.info = {"category":"info","details":[""]}

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

    # if (len(is_malicious["info"]["details"]) > 1): #Si est suspect, on drop en affichant le log
    #     print(is_malicious["info"])


if __name__ == "__main__":
    # Démarrer la capture de paquets
    sniff(prn=packet_capture,store=False)


    # Compresser le fichier pcapng de sortie avec gzip
    with open('packets.pcapng', 'rb') as f_in:
        with gzip.open('packets.pcapng.gz', 'wb') as f_out:
            f_out.writelines(f_in)
