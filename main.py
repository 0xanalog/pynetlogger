import gzip
import json
import requests
import time
from scapy.all import *



LOG_SERVER_URL  = 'http://192.168.1.21:8080/logs'

malicious_ips   = ["44.32.214.17","google.fr"]
malicious_ports = [1234,4321,6666]



# Fonction d'envoi des logs JSON au serveur distant
def send_logs(logs):
    response = requests.post(LOG_SERVER_URL, json=logs)
    if response.status_code != 200:
        print('Erreur lors de l\'envoi des logs au serveur distant')


def is_malicious(pkt : Packet) -> dict[str,str]:
    ret = {"category":"info", "details":""}

    #len check
    if (len(pkt) > 65535):
        ret = {"category":"WARN", "details":"exceeded ip length"}

    #blacklist check
    if (packet[IP].src in malicious_ips or packet[IP].dst in malicious_ips):
        if (packet[UDP].sport in malicious_ports or packet[UDP].dport in malicious_ports):
            ret = {"category":"WARN", "details":"blacklisted access"}

    #ARP
    if (pkt.haslayer(ARP)): 
        if (pkt[ARP][6:2] == 2):
            ret = {"category":"WARN", "details":"arp poisonning"}

    #ICMP
    elif (pkt.haslayer(ICMP)):
        if (len(packet[ICMP]) > 65535):
            ret = {"category":"WARN", "details":"ping of death"}

        if(pkt and (pkt[ICMP][0] == 8 or pkt[ICMP][0] == 0) and pkt[ICMP][1] == 0):
            ret = {"category":"WARN", "details":"icmp flood"}
    
    #SYN
    elif (pkt.haslayer(TCP)): 
        if (pkt[TCP].flags == "S"):
            ret = {"category":"WARN", "details":"syn flood"}

        if(pkt[TCP][13] == 2 or pkt[TCP][13] == 18 or pkt[TCP][13] == 20):
            ret = {"category":"WARN", "details":"malicious tcp"}

    #DNS
    elif (pkt.haslayer(DNSQR)):
        if (pkt[DNSQR].qtype == 1 and pkt[DNSQR].qclass == 1):
            ret = {"category":"WARN", "details":"dns amplification"}

    elif (pkt.haslayer(Raw) and pkt[Raw].dport == 3306):
        if ("SELECT" or "DROP" or "GET" in str(pkt[Raw].load)):
            ret = {"category":"WARN", "details":"sqli"}

    return ret



def packet_capture(pkt):
    # Enregistrer le paquet dans le fichier pcapng
    wrpcap('packets.pcapng', pkt, append=True)

    # Créer le log JSON correspondant au paquet capturé
    log = {
        'timestamp': time.time(),
        'packet': str(pkt),
        'info':is_malicious(pkt)
    }

    # Envoyer le log JSON au serveur distant
    send_logs(log)

# Démarrer la capture de paquets
sniff(prn=packet_capture)


# Compresser le fichier pcapng avec gzip
with open('packets.pcapng', 'rb') as f_in:
    with gzip.open('packets.pcapng.gz', 'wb') as f_out:
        f_out.writelines(f_in)