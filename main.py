import socket
import struct
from scapy.all import Ether, ARP, srp



def scan_network(ip):
    # Envoie un paquet ARP pour trouver les adresses MAC
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, iface=None, verbose=False)

    # Affiche les adresses IP et MAC trouvées
    print("Adresses IP/MAC trouvées :")
    for snd, rcv in ans:
        print("-------------------------------")
        print(rcv.sprintf(r"Adresse MAC: %ARP.psrc%" + "\n"
                          "Addresse IP: %Ether.src%"))
        print("-------------------------------")


def get_cidr():
    while True:
        cidr = input("Entrez le masque de sous-réseau en format CIDR (ex. /24) : ")
        try:
            if not cidr.startswith("/"):
                raise ValueError("Le format du masque de sous-réseau n'est pas valide")
            cidr_value = int(cidr[1:])
            if cidr_value < 0 or cidr_value > 32:
                raise ValueError("Le masque de sous-réseau doit être compris entre /0 et /32")
            return cidr
        except ValueError as e:
            print(e)

def get_ip_address():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    return s.getsockname()[0]


if __name__ == "__main__":
    # Définit la plage d'adresses IP à numériser

    # Obtenir l'adresse IP locale
    ip = socket.gethostbyname(socket.gethostname())

    # Obtenir le masque de sous-réseau
    netmask = socket.inet_ntoa(struct.pack('!I', struct.unpack('!I', socket.inet_aton(socket.gethostbyname(socket.gethostname())))[0] & 0xffffff00))
    
    # Calculer l'adresse réseau
    network = socket.inet_ntoa(struct.pack('!I', struct.unpack('!I', socket.inet_aton(ip))[0] & struct.unpack('!I', socket.inet_aton(netmask))[0]))
    
    cidr = get_cidr()
    # Concaténer l'adresse IP et le masque de sous-réseau pour définir la plage d'adresses IP à numériser
    
    network = network + cidr
    print(network)

    scan_network(network)
