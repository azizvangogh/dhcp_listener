from scapy.all import *
import time


# DHCP DİNLEME
# DHCP AYNI WİFİ DE Kİ CİHAZLARIN UDP YOLUYLA İLETİŞİME GEÇMESİ PAKET YOLLAMASIDIR.

def listen_dhcp():
    sniff(prn=print_packet, filter='udp and (port 67 or port 68)')


def print_packet(packet):
    # DEĞERLERİ KURMA
    # DHCP SERVER IP ADRESİ
    target_mac , requested_ip , hostname , vendor_id = [None] * 4
    # DHCP SERVER IP ADRESİ
    if packet.haslayer(Dot11):
        target_mac = packet.getlayer(Ether).src

    dhcp_options = packet.(DHCP).options
    for item in dhcp_options:
        try:
            label, value = item
        except ValueError:
            continue
        if label == 'requested_addr':
            # get the requested IP
            requested_ip = value
        elif label == 'hostname':
            # get the hostname of the device
            hostname = value.decode()
        elif label == 'vendor_class_id':
            # get the vendor ID
            vendor_id = value.decode()


        if target_mac and vendor_id and hostname and requested_ip:
            time_now = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            print(f"{time_now} - {target_mac} - {vendor_id} - {hostname} - {requested_ip}")


        if __name__ == "__main__":
            listen_dhcp()



