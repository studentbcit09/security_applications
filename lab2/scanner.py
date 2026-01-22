import nmap

def port_scanning():
    port_scanner = nmap.PortScanner()
    
    host = input("IP address: ")
    port_range = '20-1024'

    results = port_scanner.scan(host, port_range, '-sV')
    print('host: %s (%s)' % (host, port_scanner[host].hostname()))
    print('state: %s' % port_scanner[host].state())
    
    for protocol in port_scanner[host].all_protocols():
        print('Protocol: %s' % protocol)

        port_status = port_scanner[host][protocol].keys()
        port_status.sort()

        for port in port_status:
            port_info = port_scanner[host][protocol][port]
            # if 'open' == state:
            if 'name' in port_info:
                print('port: %s state: %s service: %s' % (port, port_info['state'], port_info['name']))
            else:
                print('port: %s, state: %s' % port, port_info['state'])
        
            

