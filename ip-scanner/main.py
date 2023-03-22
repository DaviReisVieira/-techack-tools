import nmap
import manuf
from scapy.all import ARP, Ether, srp, conf

tcp_ports = {
    7: "Echo",
    20: "FTP (Data)",
    21: "FTP (Control)",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP (Server)",
    68: "DHCP (Client)",
    80: "HTTP",
    110: "POP3",
    119: "NNTP",
    123: "NTP",
    143: "IMAP4",
    161: "SNMP",
    194: "IRC",
    443: "HTTPS",
    465: "SMTPS",
    587: "SMTP (Submission)",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS Proxy",
    1433: "Microsoft SQL Server",
    1434: "Microsoft SQL Monitor",
    1521: "Oracle Database",
    1723: "PPTP",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    8080: "HTTP Proxy",
    8443: "HTTPS Alt",
    9100: "Printer",
    9200: "Elasticsearch",
    9300: "Elasticsearch",
    9999: "Telnet (Alt)",
    10000: "Webmin",
    27017: "MongoDB",
    27018: "MongoDB",
    28017: "MongoDB HTTP",
    50000: "SAP Router",
    54321: "Booby Trap",
    60000: "DeepThroat",
}

def print_port(port, information, is_well_port = False):
    print("\n" + "_"*45)
    print("Porta: "+ str(port) if not is_well_port else "Porta: "+ str(port) + " | Well Port: " + tcp_ports[port])
    print(" - " + "Status: " + information["state"])
    print(" - " + "Serviço: " + information["name"])
    print(" - " + "Versão: " + information["version"])
    print(" - " + "Produto: " + information["product"])
    print(" - " + "CPE: " + information["cpe"])
    print(" - " + "Extrainfo: " + information["extrainfo"])
    print(" - " + "Confiança: " + str(information["conf"]))

def escanear_rede():
    print("Selecione o IP da rede e a máscara que deseja escanear (Ex: 192.168.0.0/24):")
    network_ip = input(">> ")

    conf.verb = 0
    conf.timeout = 3

    arp = ARP(pdst=network_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")

    packet = ether/arp

    print("\nEscaneando Rede... Aguarde.\n")
    macFinder = manuf.MacParser()

    result = srp(packet, timeout=3, verbose=0)[0]
    
    print("-" * 45)
    for sent, received in result:
        mac = received.hwsrc
        manufacturer = macFinder.get_manuf(mac)
        print(f"Device found: IP = {received.psrc}, MAC = {mac}, Manufacturer = {manufacturer}")
    

def escanear_host():
    print("-" * 45)
    print("Digite o endereço IP ou nome do host: ")
    host = input(">> ")

    print("Deseja escanear apenas as Well Know Ports?[y/n]")
    well_knows = input(">> ")
    

    if well_knows.upper() == "Y" or well_knows.upper() == "S":
        WELL_KNOW_PORTS = ",".join([str(i) for i in tcp_ports])
        arguments_np = f"-sV -p {WELL_KNOW_PORTS}"
        is_well_port = True
    elif well_knows.upper() == "N":
        inicio = int(input("Digite o número da porta inicial: "))
        fim = int(input("Digite o número da porta final: "))
        arguments_np = f"sV -p {inicio}-{fim}"
    else:
        print("\nOpção inválida! Tente novamente.\n")
        return

    nm = nmap.PortScanner()
    print("Iniciando escaneamento... Aguarde.\n")
    resultado = nm.scan(host, arguments = arguments_np)

    ports = [i for i in resultado['scan'][host]['tcp']]

    print(f"\nHost: {host}")
    print("Portas localizadas:")
    print(ports)
    for porta in ports:
        information = resultado['scan'][host]['tcp'][porta]
        estado = information['state']
        if estado == 'open':
            print_port(porta, information, is_well_port)


def select_ip_scanner_option():
    print("-" * 45)
    print("Escolha um opção para continuar...")
    print("1 - Escanear Rede")
    print("2 - Escanear IP")
    print("3 - Sair")
    return input(">> ")

def exit_layout():
    print("-" * 45)
    print("Escaneamentos de Portas TCP encerrado.")
    print("-" * 45)

def main():
    print("Ferramenta de Escaneamento de Portas TCP")
    print("GitHub: DaviReisVieira")
    print("-" * 45)

    ip_scanner = True

    while ip_scanner:
        select_option = select_ip_scanner_option()

        if select_option == "1":
            escanear_rede()
        elif select_option == "2":
            escanear_host()
        elif select_option == "3":
            ip_scanner = False
            exit_layout()
        else:
            print("\nOpção inválida! Tente novamente.\n")


if __name__ == "__main__":
    main()
