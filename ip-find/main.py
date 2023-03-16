import nmap

# create a new nmap scanner object
nm = nmap.PortScanner()

# scan the network for hosts
nm.scan(hosts='192.168.1.0/24', arguments='-n -sP')

# print the list of all hosts that were found
for host in nm.all_hosts():
    print('Host : %s (%s)' % (host, nm[host].hostname()))