import nmap
def ipscan(ip):
    h={}
    nmScan = nmap.PortScanner()
    nmScan.scan(hosts=ip, arguments='-n -sP')
    hosts_list = [(x, nmScan[x]['status']['state']) for x in nmScan.all_hosts()]
    for host, status in hosts_list:
        h[host] = status
    return h

def detscan(ip,port):
    dlist=[]
    nmScan = nmap.PortScanner()
    machine = nmScan.scan(ip, port, '-O')
    for host in nmScan.all_hosts():
        hostdict = {}
        hostdict['Host'] = host
        hostdict['Host name'] = nmScan[host].hostname()
        os_matches = machine['scan'][host]['osmatch']
        if os_matches:
            hostdict['OS'] = os_matches[0]['name']
        else:
            hostdict['OS'] = 'N/A'

        for proto in nmScan[host].all_protocols():
            hostdict['Protocol'] = proto
            dlist.append(hostdict)

            lport = nmScan[host][proto].keys()
            for port in lport:
                portdict = {}
                portdict['Port'] = port
                portdict['State'] = nmScan[host][proto][port]['state']
                portdict['Service'] = nmScan[host][proto][port]['name']
                portdict['Reason'] = nmScan[host][proto][port]['reason']
                dlist.append(portdict)
    
    return dlist
                