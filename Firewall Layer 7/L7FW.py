#Biblioteci necesare pentru construirea interfetei grafice a aplicatiei
#tkinter este o biblioteca standard din python pentru crearea de interfete grafice
import tkinter as tk
#ttk(Themed Tkinter) ofera widget-uri stilizate cu ari fi Treeview, care permite afisarea datelor in forma tabelara
from tkinter import ttk
#customtkinter este o extensie pentru tkinter care permite crearea de interfete grafice cu un aspect mai modern si personalizat
import customtkinter as ctk

from queue import Queue #queue ofera o structura de coada pentru gestionarea pachetelor capturate
import socket   #biblioteca standard pentru manipularea pachetelor brute
import struct   #permite manipularea datelor binare, inclusiv extragerea si crearea de structuri de date din pachetele de retea
import threading    #permite capturarea pachetelor in fundal, fara a bloca interfata grafica si ajuta la actualizarea tabelului de pachete
import time

packet_queue = Queue()  #Coada pentru stocare pachetelor capturate, permite transferul acestor pachete dintr-un fir de executie in altul fara conflicte
captured_packets = []   #Lista care stocheaza toate pachetele capturate impreuna cu toate informatiile acestora(adrese IP, protocol, etc.)
active_rules=[]     #Stocheaza regulile de filtrare a traficului introduse de utilizator

#Functie pentru capturarea si procesarea pachetelor
def sniff_packets():

    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP) #creaza un socket brut pentru capturarea pachetelor IP
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)   #Seteaza optiunea ca header-ul IP sa fie inclus in pachetele capturate
    local_ip = socket.gethostbyname(socket.gethostname())         # Obtine adresa Ip locala a masinii gazda
    s.bind((local_ip, 0))   #Leaga socket-ul creat de adresa ip locala
    s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)    #porneste modul promiscuous care permite capturarea completa a traficului de retea pe masina locala

    packet_no = 1
    while True:
        packet, addr = s.recvfrom(65535)    #primeste un pachet de dimensiune maxima de 65535 bytes
        ip_header = packet[:20]     #se extrag primii 20 de bytes ai pachetului, care reprezinta headerul de IP
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header) #Headerul IP este despachetat
        #Se stocheaza informatiile despachetate in dictionarul ip_info
        ip_info = {
            "IP_Version": iph[0] >> 4,
            "IP_IHL": iph[0] & 0xF,
            "IP_TOS": iph[1],
            "IP_Total Length": iph[2],
            "IP_ID": iph[3],
            "IP_Flags": (iph[4] >> 13) & 0x7,
            "IP_Fragment Offset": iph[4] & 0x1FFF,
            "IP_TTL": iph[5],
            "IP_Protocol": iph[6],
            "IP_Checksum": iph[7],
            "IP_Source IP": socket.inet_ntoa(iph[8]),
            "IP_Destination IP": socket.inet_ntoa(iph[9]),
        }
        #In iph[6] se afla protocolul IP (ICMP,TCP,UDP de exemplu)
        if iph[6] == 1:  # ICMP
            icmp_info = parse_icmp_header(packet[20:28])
            ip_info.update(icmp_info)
        elif iph[6] == 6:  # TCP
            tcp_info = parse_tcp_header(packet[20:40])
            ip_info.update(tcp_info)
            # Analizam payload-ul pentru TCP si SSH
            payload = packet[40:]
            if payload.startswith(b"SSH-"):  # SSH Handshake
                ssh_info = parse_ssh_header(payload)
                ip_info.update(ssh_info)
            elif b"HTTP" in payload or b"GET" in payload or b"POST" in payload:  # Trafic HTTP
                http_info = parse_http_header(payload)
                ip_info.update(http_info)
        elif iph[6] == 17:  # UDP
            udp_info = parse_udp_header(packet[20:28])
            ip_info.update(udp_info)

            # Verificam pentru DNS
            udp_src_port = udp_info["UDP_Source Port"]
            udp_dst_port = udp_info["UDP_Destination Port"]
            if udp_src_port == 53 or udp_dst_port == 53:
                dns_info = parse_dns_header(packet[28:])
                ip_info.update(dns_info)

        displayed_info = " | ".join(
            f"{key.split('_')[1]}: {value}"
            for key, value in ip_info.items()
            if key in checked_fields and checked_fields[key].get()
        )

        # Stocam datele pentru actualizare
        captured_packets.append({
            "No": packet_no,
            "Time": time.strftime("%H:%M:%S"),
            "Src IP": ip_info["IP_Source IP"],
            "Dst IP": ip_info["IP_Destination IP"],
            "Protocol": ip_info["IP_Protocol"],
            "Info": ip_info,
        })

        packet_queue.put({
            "No": packet_no,
            "Time": time.strftime("%H:%M:%S"),
            "Src IP": ip_info["IP_Source IP"],
            "Dst IP": ip_info["IP_Destination IP"],
            "Protocol": ip_info["IP_Protocol"],
            "Info": displayed_info,
        })
        packet_no += 1

#Functiile de parse pentru protocoalele incluse, aceste functii analizeaza headerele si extrag informatiile importante din acestea
def parse_icmp_header(packet):
    icmp_header = struct.unpack('!BBH4s', packet[:8])
    return {
        "ICMP_Type": icmp_header[0],
        "ICMP_Code": icmp_header[1],
        "ICMP_Checksum": icmp_header[2],
        "ICMP_Other Info": icmp_header[3].hex(),
    }

def parse_tcp_header(packet):
    tcp_header = struct.unpack('!HHLLBBHHH', packet[:20])
    offset = (tcp_header[4] >> 4) * 4
    return {
        "TCP_Source Port": tcp_header[0],
        "TCP_Destination Port": tcp_header[1],
        "TCP_Sequence Number": tcp_header[2],
        "TCP_Acknowledgment Number": tcp_header[3],
        "TCP_Offset": offset,
        "TCP_Reserved": (tcp_header[4] >> 1) & 0x7,
        "TCP_Flags": tcp_header[5],
        "TCP_Window": tcp_header[6],
        "TCP_Checksum": tcp_header[7],
        "TCP_Urgent Pointer": tcp_header[8],
    }

def parse_udp_header(packet):
    udp_header = struct.unpack('!HHHH', packet[:8])
    return {
        "UDP_Source Port": udp_header[0],
        "UDP_Destination Port": udp_header[1],
        "UDP_Length": udp_header[2],
        "UDP_Checksum": udp_header[3],
    }

def parse_http_header(payload):
    sections = payload.decode("utf-8", errors="ignore").split("\r\n\r\n", 1)    #Se transforma datele binare in caractere
    header = sections[0]  # Partea de header HTTP
    http_info = {}  #initializare dictionar gol pentru a stoca informatiile

    lines = header.split("\r\n")    #imparte headerul in linii separate

    if lines[0].startswith(("GET", "POST", "PUT", "DELETE")):  #verificare daca este o cerere HTTP
        method, url, version = lines[0].split()
        http_info["HTTP_Method"] = method
        http_info["HTTP_URL"] = url
        http_info["HTTP_Version"] = version
    elif lines[0].startswith("HTTP/"):  #verificare daca este un raspuns
        version, status_code, _ = lines[0].split(maxsplit=2)
        http_info["HTTP_Version"] = version
        http_info["HTTP_Status-Code"] = status_code

    essential_fields = ["Host", "User-Agent", "Content-Type", "Content-Length", "Connection"] #lista cu cele mai importante elemente din header

    #Se extrag restul de elemente din header
    for line in lines[1:]:
        if ": " in line:
            key, value = line.split(": ", 1)
            key = key.strip()
            value = value.strip()
            if key in essential_fields:
                http_info[f"HTTP_{key.replace('-', '_')}"] = value

    # Extragem payloadul pentru POST
    if len(sections) > 1 and sections[1].strip():
        http_info["HTTP_Payload"] = sections[1].strip()
    else:
        http_info["HTTP_Payload"] = "No Payload"

    return http_info


def parse_ssh_header(payload):
    ssh_info = {}
    try:
        header = payload.decode("utf-8", errors="ignore")
        if header.startswith("SSH-"):
            parts = header.split(" ", 2)
            ssh_info["SSH_Protocol Version"] = parts[0]
            ssh_info["SSH_Software"] = parts[1] if len(parts) > 1 else "Unknown"
        ssh_info["SSH_Message Type"] = f"Encrypted Payload (Length: {len(payload)})"
    except UnicodeDecodeError:
        ssh_info["SSH_Message Type"] = "Non-readable Payload"
    return ssh_info

def parse_dns_header(payload):
    dns_header = struct.unpack('!HHHHHH', payload[:12])
    return {
        "DNS_Transaction ID": dns_header[0],
        "DNS_Flags": dns_header[1],
        "DNS_Questions": dns_header[2],
        "DNS_Answer RRs": dns_header[3],
        "DNS_Authority RRs": dns_header[4],
        "DNS_Additional RRs": dns_header[5],
    }

#Functie care afiseaza detaliile complete ale unui pachet pe toate cele 3 layere. Este apelata atunci cand se face click pe unul dintre pachete, moment in care se deschide o fereastra care afiseaza toate elementele header-elor specifice pachetului
def show_packet_details(packet_info):
    details_window = tk.Toplevel()
    details_window.title("Packet Details")
    details_window.geometry("700x400")

    details_text=""

    if any(key.startswith("IP_") for key in packet_info["Info"].keys()):
        details_text += "------------IP------------\n"
        details_text += "\n".join(
            f"{key.split('_')[1]}: {value}"
            for key, value in packet_info["Info"].items()
            if key.startswith("IP_") and key in checked_fields and checked_fields[key].get()
        ) + "\n\n"

    if any(key.startswith("ICMP_") for key in packet_info["Info"].keys()):
        details_text += "------------ICMP------------\n"
        details_text += "\n".join(
            f"{key.split('_')[1]}: {value}"
            for key, value in packet_info["Info"].items()
            if key.startswith("ICMP_") and key in checked_fields and checked_fields[key].get()
        ) + "\n\n"

    if any(key.startswith("TCP_") for key in packet_info["Info"].keys()):
        details_text += "------------TCP------------\n"
        details_text += "\n".join(
            f"{key.split('_')[1]}: {value}"
            for key, value in packet_info["Info"].items()
            if key.startswith("TCP_") and key in checked_fields and checked_fields[key].get()
        ) + "\n\n"

    if any(key.startswith("UDP_") for key in packet_info["Info"].keys()):
        details_text += "------------UDP------------\n"
        details_text += "\n".join(
            f"{key.split('_')[1]}: {value}"
            for key, value in packet_info["Info"].items()
            if key.startswith("UDP_") and key in checked_fields and checked_fields[key].get()
        ) + "\n\n"

    if any(key.startswith("HTTP_") for key in packet_info["Info"].keys()):
        details_text += "------------HTTP------------\n"
        details_text += "\n".join(
            f"{key.split('_', 1)[1]}: {value}"
            for key, value in packet_info["Info"].items()
            if key.startswith("HTTP_") and key in checked_fields and checked_fields[key].get()
        ) + "\n\n"
        if "HTTP_Payload" in packet_info["Info"] and packet_info["Info"]["HTTP_Payload"] != "No Payload":
            details_text += f"Payload: {packet_info['Info']['HTTP_Payload']}\n\n"

    if any(key.startswith("SSH_") for key in packet_info["Info"].keys()):
        details_text += "------------SSH------------\n"
        details_text += "\n".join(
            f"{key.split('_')[1]}: {value}"
            for key, value in packet_info["Info"].items()
            if key.startswith("SSH_") and key in checked_fields and checked_fields[key].get()
        ) + "\n\n"

    if any(key.startswith("DNS_") for key in packet_info["Info"].keys()):
        details_text += "------------DNS------------\n"
        details_text += "\n".join(
            f"{key.split('_')[1]}: {value}"
            for key, value in packet_info["Info"].items()
            if key.startswith("DNS_") and key in checked_fields and checked_fields[key].get()
        ) + "\n\n"

    info_label = tk.Label(
        details_window, text=details_text, justify="left", anchor="nw", wraplength=680
    )
    info_label.pack(fill="both", expand=True, padx=10, pady=10)

#Functie pentru maparea protocolului de ip in valoare numerica la denumirea lui
def get_protocol_name(protocol_number):
    protocol_map = {
        1: "ICMP",
        6: "TCP",
        17: "UDP",
        2: "IGMP"
    }
    return protocol_map.get(protocol_number, f"Unknown ({protocol_number})")


#Creaza interfata grafica principala
def start_gui():
    app = ctk.CTk() #Se foloseste libraria customtkinter
    app.title("Firewall Monitor")
    app.geometry("1920x1080")

    global checked_fields  #Dictionar global pentru toate campurile pachetelor
    checked_fields = {}

    #Se creaza dictionare care contin toate campurile relevante ale protocoalelor
    #Aceste dictionare sunt asociate cu niste checkboxuri care au ca scop bifarea informatiilor pe care utilizatorul vrea sa le vada

    #IP
    ip_fields = {
        "IP_Version": tk.BooleanVar(value=True),
        "IP_IHL": tk.BooleanVar(value=True),
        "IP_TOS": tk.BooleanVar(value=True),
        "IP_Total Length": tk.BooleanVar(value=True),
        "IP_ID": tk.BooleanVar(value=True),
        "IP_Flags": tk.BooleanVar(value=True),
        "IP_Fragment Offset": tk.BooleanVar(value=True),
        "IP_TTL": tk.BooleanVar(value=True),
        "IP_Protocol": tk.BooleanVar(value=True),
        "IP_Checksum": tk.BooleanVar(value=True),
        "IP_Source IP": tk.BooleanVar(value=True),
        "IP_Destination IP": tk.BooleanVar(value=True),
    }

    #ICMP
    icmp_fields = {
        "ICMP_Type": tk.BooleanVar(value=True),
        "ICMP_Code": tk.BooleanVar(value=True),
        "ICMP_Checksum": tk.BooleanVar(value=True),
        "ICMP_Other Info": tk.BooleanVar(value=True),
    }

    #TCP
    tcp_fields = {
        "TCP_Source Port": tk.BooleanVar(value=True),
        "TCP_Destination Port": tk.BooleanVar(value=True),
        "TCP_Sequence Number": tk.BooleanVar(value=True),
        "TCP_Acknowledgment Number": tk.BooleanVar(value=True),
        "TCP_Offset": tk.BooleanVar(value=True),
        "TCP_Reserved": tk.BooleanVar(value=True),
        "TCP_Flags": tk.BooleanVar(value=True),
        "TCP_Window": tk.BooleanVar(value=True),
        "TCP_Checksum": tk.BooleanVar(value=True),
        "TCP_Urgent Pointer": tk.BooleanVar(value=True),
    }

    #UDP
    udp_fields = {
        "UDP_Source Port": tk.BooleanVar(value=True),
        "UDP_Destination Port": tk.BooleanVar(value=True),
        "UDP_Length": tk.BooleanVar(value=True),
        "UDP_Checksum": tk.BooleanVar(value=True),
    }

    #HTTP
    http_fields = {
        "HTTP_Method": tk.BooleanVar(value=True),
        "HTTP_URL": tk.BooleanVar(value=True),
        "HTTP_Version": tk.BooleanVar(value=True),
        "HTTP_Status_Code": tk.BooleanVar(value=True),
        "HTTP_Host": tk.BooleanVar(value=True),
        "HTTP_User_Agent": tk.BooleanVar(value=True),
        "HTTP_Content_Type": tk.BooleanVar(value=True),
        "HTTP_Content_Length": tk.BooleanVar(value=True),
        "HTTP_Connection": tk.BooleanVar(value=True),
    }

    #SSH
    ssh_fields = {
        "SSH_Protocol Version": tk.BooleanVar(value=True),
        "SSH_Software": tk.BooleanVar(value=True),
        "SSH_Message Type": tk.BooleanVar(value=True),
    }

    #DNS
    dns_fields = {
        "DNS_Transaction ID": tk.BooleanVar(value=True),
        "DNS_Flags": tk.BooleanVar(value=True),
        "DNS_Questions": tk.BooleanVar(value=True),
        "DNS_Answer RRs": tk.BooleanVar(value=True),
        "DNS_Authority RRs": tk.BooleanVar(value=True),
        "DNS_Additional RRs": tk.BooleanVar(value=True),
    }

    # Se adauga toate campurile la checked_fields(checkboxuri)
    checked_fields.update(ip_fields)
    checked_fields.update(icmp_fields)
    checked_fields.update(tcp_fields)
    checked_fields.update(udp_fields)
    checked_fields.update(http_fields)
    checked_fields.update(ssh_fields)
    checked_fields.update(dns_fields)

    # Frame pentru tabelul cu pachete
    table_frame = ctk.CTkFrame(app, corner_radius=10)
    table_frame.place(relx=0.22, rely=0.15, relwidth=0.5, relheight=0.7)
    #Tabelul cu pachete
    table_scroll_y = ttk.Scrollbar(table_frame, orient="vertical")
    table_scroll_x = ttk.Scrollbar(table_frame, orient="horizontal")
    table_columns = ["No", "Time", "Src IP", "Dst IP", "Protocol", "Info"]
    table = ttk.Treeview(
        table_frame, columns=table_columns, show="headings",
        yscrollcommand=table_scroll_y.set, xscrollcommand=table_scroll_x.set
    )

    #Multe optiuni de stil pentru vederea mai clara a tabelului
    table_scroll_y.config(command=table.yview)
    table_scroll_x.config(command=table.xview)

    table_scroll_y.pack(side="right", fill="y")
    table_scroll_x.pack(side="bottom", fill="x")
    table.pack(fill="both", expand=True, padx=5, pady=5)

    for col in table_columns:
        table.heading(col, text=col)
        table.column(col, anchor="center", stretch=True, width=150)

    style = ttk.Style()
    style.theme_use("default")
    style.configure(
        "Treeview.Heading",
        font=("Helvetica", 12, "bold"),
        background="#2a2a2a",
        foreground="white",
        relief="solid"
    )
    style.configure(
        "Treeview",
        font=("Helvetica", 10),
        rowheight=25,
        fieldbackground="white",
        highlightthickness=1,
        highlightcolor="black"
    )
    style.layout("Treeview", [("Treeview.treearea", {"sticky": "nswe"})])

    # Functie care actualizeza coloana de INFO din tabel in functie de checkboxurile bifate
    def update_info():
        for index, item in enumerate(table.get_children()):
            packet = captured_packets[index]
            ip_info = packet["Info"]
            displayed_info = " | ".join(
                f"{key.split('_')[1]}: {value}"
                for key, value in ip_info.items()
                if key in checked_fields and checked_fields[key].get()
            )
            table.item(item, values=[
                packet["No"], packet["Time"], packet["Src IP"],
                packet["Dst IP"], packet["Protocol"], displayed_info
            ])

    #Actualizeaza tabelul principal cu pachete noi capurate sau filtrate
    def update_table(filtered_packets=None):

        # Se goleste tabelul
        for item in table.get_children():
            table.delete(item)

        # Selecteaza pachetele care trebuie afisate
        packets = filtered_packets if filtered_packets else captured_packets

        for packet in packets:
            status = apply_active_filter(packet)  # Determina starea pachetului(blocat sau acceptat)
            tag = ""
            if status == "Block":   #Se coloreaza diferit pachetele blocate si cele acceptate
                tag = "red"
            elif status == "Accept":
                tag = "green"

            # Pachetul este adaugat in tabel
            table.insert("", "end", values=[
                packet["No"], packet["Time"], packet["Src IP"],
                packet["Dst IP"], get_protocol_name(packet["Protocol"]), f"Packet {status}"
            ], tags=(tag,))

        #se coloreaza pachetul in functie de starea acestuia
        table.tag_configure("red", background="lightcoral")
        table.tag_configure("green", background="lightgreen")

    #Creaaza frame-ul pentru checkboxuri si butoane pentru acestea
    def create_filter_frame():
        filter_frame = ctk.CTkFrame(app, corner_radius=10)
        filter_frame.place(relx=0, rely=0.1, relwidth=0.2, relheight=0.8)

        filter_scroll_y = ttk.Scrollbar(filter_frame, orient="vertical")
        filter_canvas = tk.Canvas(filter_frame, yscrollcommand=filter_scroll_y.set, bg="black")
        filter_scroll_y.config(command=filter_canvas.yview)
        filter_scroll_y.pack(side="right", fill="y")
        filter_canvas.pack(side="left", fill="both", expand=True)

        filter_inner_frame = tk.Frame(filter_canvas, bg="black")
        filter_canvas.create_window((0, 0), window=filter_inner_frame, anchor="nw")

        # Butoane Select All / Deselect All
        button_frame = tk.Frame(filter_inner_frame, bg="white")
        button_frame.pack(fill="x", pady=5)

        select_all_button = tk.Button(button_frame, text="Select All", command=select_all)
        select_all_button.pack(side="left", padx=10)

        deselect_all_button = tk.Button(button_frame, text="Deselect All", command=deselect_all)
        deselect_all_button.pack(side="left", padx=10)

        def on_configure(event):
            filter_canvas.configure(scrollregion=filter_canvas.bbox("all"))

        filter_inner_frame.bind("<Configure>", on_configure)


        #Sectiuni de checkboxuri pentru fiecare element din header-ele protocoalelor
        tk.Label(filter_inner_frame, text="Layer 3: IP", font=("Helvetica", 12, "bold"), bg="white", fg="black", anchor="w").pack(fill="x", padx=10, pady=5)
        for field, var in ip_fields.items():
            ctk.CTkCheckBox(
                filter_inner_frame, text=field, variable=var, command=update_info
            ).pack(anchor="w", padx=10)

        tk.Label(filter_inner_frame, text="Layer 3: ICMP", font=("Helvetica", 12, "bold"), bg="white", fg="black", anchor="w").pack(fill="x", padx=10, pady=5)
        for field, var in icmp_fields.items():
            ctk.CTkCheckBox(
                filter_inner_frame, text=field, variable=var, command=update_info
            ).pack(anchor="w", padx=10)

        tk.Label(filter_inner_frame, text="Layer 4: TCP", font=("Helvetica", 12, "bold"), bg="white", fg="black", anchor="w").pack(fill="x", padx=10, pady=5)
        for field, var in tcp_fields.items():
            ctk.CTkCheckBox(
                filter_inner_frame, text=field, variable=var, command=update_info
            ).pack(anchor="w", padx=10)

        tk.Label(filter_inner_frame, text="Layer 4: UDP", font=("Helvetica", 12, "bold"), bg="white", fg="black", anchor="w").pack(fill="x", padx=10, pady=5)
        for field, var in udp_fields.items():
            ctk.CTkCheckBox(
                filter_inner_frame, text=field, variable=var, command=update_info
            ).pack(anchor="w", padx=10)

        tk.Label(filter_inner_frame, text="Layer 7: HTTP", font=("Helvetica", 12, "bold"), bg="white", fg="black",
                 anchor="w").pack(fill="x", padx=10, pady=5)
        for field, var in http_fields.items():
            ctk.CTkCheckBox(
                filter_inner_frame, text=field, variable=var, command=update_info
            ).pack(anchor="w", padx=10)

        tk.Label(filter_inner_frame, text="Layer 7: SSH", font=("Helvetica", 12, "bold"), bg="white", fg="black",
                 anchor="w").pack(fill="x", padx=10, pady=5)
        for field, var in ssh_fields.items():
            ctk.CTkCheckBox(
                filter_inner_frame, text=field, variable=var, command=update_info
            ).pack(anchor="w", padx=10)

        tk.Label(filter_inner_frame, text="Layer 7: DNS", font=("Helvetica", 12, "bold"), bg="white", fg="black",
                 anchor="w").pack(fill="x", padx=10, pady=5)
        for field, var in dns_fields.items():
            ctk.CTkCheckBox(
                filter_inner_frame, text=field, variable=var, command=update_info
            ).pack(anchor="w", padx=10)

    #Functia care deschide fereastra cu informatii atunci cand se apasa click pe un pachet
    def on_table_click(event):
        selected_item = table.focus()
        if selected_item:
            packet_info = table.item(selected_item, "values")
            packet = next((pkt for pkt in captured_packets if str(pkt["No"]) == packet_info[0]), None)
            if packet:
                show_packet_details(packet)  # Afișăm detaliile


    #Functia pentru butonul de bifare a tuturor checkboxurilor
    def select_all():
        for var in checked_fields.values():
            var.set(True)
        update_info()

    # Functia pentru butonul de debifare a tuturor checkboxurilor
    def deselect_all():
        for var in checked_fields.values():
            var.set(False)
        update_info()

    # Frame pentru filtrarea pasivă
    filter_search_frame = ctk.CTkFrame(app, corner_radius=10)
    filter_search_frame.place(relx=0.01, rely=0.01, relwidth=0.55, relheight=0.05)

    filter_entry = tk.Entry(filter_search_frame, width=80, font=("Helvetica", 12))
    filter_entry.pack(side="left", padx=10, pady=10)


    #Functie de filtrare pasiva. Filtreaza pachetele afisate in tabel pe baza unor conditii introduse in filter_entrty
    def apply_passive_filter():
        # Obtine regulile introduse
        query = filter_entry.get()
        if query:
            filtered_packets = filter_packets(query)
            update_table(filtered_packets)
        else:
            update_table(captured_packets)  #Daca nu exista reguli, se afiseaza toate pachetele

    #Butonul care porneste cautarea de pachete
    search_button = tk.Button(filter_search_frame, text="SEARCH", command=apply_passive_filter)
    search_button.pack(side="left", padx=10)

    #Proceseaza conditiile de filtrare si returneaza o lista de pachete care le respecta
    def filter_packets(query):
        filtered_packets = []
        try:
            conditions = query.split(",")  # Separă condițiile prin virgulă
            for packet in captured_packets:
                match = True
                for condition in conditions:
                    key, value = condition.strip().split(":")
                    key = key.strip()
                    value = value.strip()
                    if key in packet["Info"]:
                        if str(packet["Info"][key]) != value:
                            match = False
                            break
                    else:
                        match = False
                        break
                if match:
                    filtered_packets.append(packet)
        except Exception as e:
            print(f"Invalid query: {e}")
        return filtered_packets


    #Frame care retine elementele pentu filtrarea activa de pachete
    active_filter_frame = ctk.CTkFrame(app, corner_radius=10)
    active_filter_frame.place(relx=0.75, rely=0.05, relwidth=0.24, relheight=0.9)

    tk.Label(active_filter_frame, text="Active Packet Filtering", font=("Helvetica", 10, "bold")).pack(pady=10)

    #Tabelul de reguli active de filtrare
    rules_table = ttk.Treeview(
        active_filter_frame, columns=["No", "Conditions", "Action"], show="headings"
    )
    rules_table.heading("No", text="No")
    rules_table.heading("Conditions", text="Conditions")
    rules_table.heading("Action", text="Action")
    rules_table.pack(fill="both", expand=True, padx=5, pady=5)


    #Adauga o regula noua de filtrare in tabelul de reguli active de filtrare
    def add_rule():
        rule_conditions = rule_entry.get()
        action = action_var.get()
        if rule_conditions and action:
            rule_no = len(active_rules) + 1
            active_rules.append({"No": rule_no, "Conditions": rule_conditions, "Action": action})
            rules_table.insert("", "end", values=[rule_no, rule_conditions, action])
            rule_entry.delete(0, tk.END)

    #Elimina o regula deja existenta de filtrare
    def remove_rule():
        selected_item = rules_table.focus()
        if selected_item:
            rule_no = int(rules_table.item(selected_item, "values")[0])
            rules_table.delete(selected_item)
            global active_rules
            active_rules = [rule for rule in active_rules if rule["No"] != rule_no]

    #Verifica daca un pachet respecta regulile active de filtrare
    def apply_active_filter(packet_info):
        for rule in active_rules:
            conditions = rule["Conditions"].split(",")
            match = all(
                condition.split(":")[0].strip() in packet_info["Info"] and
                str(packet_info["Info"][condition.split(":")[0].strip()]) == condition.split(":")[1].strip()
                for condition in conditions
            )
            if match:
                return rule["Action"]   #Returneaza accept sau block
        return "Accept (by default)"   #Returneaza accept by default in cazul in care nu exista o regula pentru pachetul curent

    rule_entry = tk.Entry(active_filter_frame, width=20)
    rule_entry.pack(pady=5)

    action_var = tk.StringVar(value="Block")
    tk.Radiobutton(active_filter_frame, text="Block", variable=action_var, value="Block").pack(anchor="w")
    tk.Radiobutton(active_filter_frame, text="Accept", variable=action_var, value="Accept").pack(anchor="w")

    tk.Button(active_filter_frame, text="Add Rule", command=add_rule).pack(pady=5)
    tk.Button(active_filter_frame, text="Remove Selected Rule", command=remove_rule).pack(pady=5)

    tk.Button(active_filter_frame, text="Apply Filters", command=apply_active_filter).pack(pady=5)

    table.bind("<Double-1>", on_table_click)

    #Se creaza frame-ul pentru checkboxuri
    create_filter_frame()

    #Ruleaza threadul pentru capturarea pachetelor
    threading.Thread(target=sniff_packets, daemon=True).start()

    #Actualizeaza in mod constant tabelul
    update_table()

    #Porneste programul
    app.mainloop()

if __name__ == "__main__":
    start_gui()
