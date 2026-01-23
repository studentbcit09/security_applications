import nmap

def port_scanning():
    port_scanner = nmap.PortScanner()
    
    host = input("IP address or hostname: ")
    port_start = input("Port range start: ")
    port_end = input("Port range end: ")

    if not port_start.isdigit() and port_end.isdigit():
        print('Invalid port inputs. Exiting')

    port_range = port_start.strip() + '-' + port_end.strip()
    results = port_scanner.scan(host, port_range, '-sV')

    # Includes failure to resolve hostname/invalid IP
    if 'error' in port_scanner.scaninfo():
        print("Error occured while scanning: %s" % port_scanner.scaninfo()['error'][0])
        return

    # Host is unreachable or scannable
    if not port_scanner.listscan():
        print("Error: Unable to reach host")
    
    host_info = port_scanner[port_scanner.listscan()[0]]
    print('host: %s (%s)' % (host, host_info.hostname()))
    print('state: %s' % host_info.state())
    
    for protocol in host_info.all_protocols():
        print('Protocol: %s' % protocol)

        port_status = host_info[protocol].keys()
        if not port_status:
            print('No open %s ports' % protocol)
        else:
            port_status.sort()

            for port in port_status:
                port_info = host_info[protocol][port]
                # if 'open' == state:
                if not port_info['name']:
                    print('port: %s, state: %s' % port, port_info['state'])
                else:
                    print('port: %s state: %s service: %s' % (port, port_info['state'], port_info['name']))

if __name__ == '__main__':
    port_scanning()
        
            

