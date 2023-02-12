import tkinter as tk
from scapy.all import Ether, ARP, srp

def scan_network(network):
    ip_list = []
    mac_list = []
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network), timeout=2)
    for snd, rcv in ans:
        ip_list.append(rcv.sprintf(r"%ARP.psrc%"))
        mac_list.append(rcv.sprintf(r"%Ether.src%"))
    return ip_list, mac_list

def display_results(ip_list, mac_list):
    result_text.delete('1.0', tk.END)
    result_text.insert(tk.END, "Adresses IP et MAC :\n")
    for i in range(len(ip_list)):
        result_text.insert(tk.END, ip_list[i] + " " + mac_list[i] + "\n")

root = tk.Tk()
root.title("Scan réseau")

network_label = tk.Label(root, text="Réseau à scanner :")
network_label.pack()

network_entry = tk.Entry(root)
network_entry.pack()

scan_button = tk.Button(root, text="Scanner", command=lambda: display_results(*scan_network(network_entry.get())))
scan_button.pack()

result_text = tk.Text(root)
result_text.pack()

root.mainloop()