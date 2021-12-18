import nmap
import time

def nmapFastScanProcess(host):
    try:
        port_list = []
        DefaultConfigTCP = '-A -T5'
        start_time = time.time()
        nmTCP = nmap.PortScanner()
        document = nmTCP.scan(hosts = host, arguments = DefaultConfigTCP)

        for host in nmTCP.all_hosts():
            print('[*] ')
            print('[*] Nmap:')
            print('[*] ----------------------------------------------------')
            print('[*] Host : %s' % (host))
            for proto in nmTCP[host].all_protocols():
                lport = nmTCP[host][proto].keys()
                for port in lport:
                    if nmTCP[host][proto][port]['state'] == 'open':
                        port_list.append(port)
        
        stop_time = time.time()
        execution_time = stop_time - start_time
        new_port_list = str(port_list)[1:-1]
        print('[*] Nmap fast scan execution time: %.4f' % execution_time + ' s')
        return document, new_port_list
    except Exception as err:
        print('[*] Exception while executing nmap: %s' % err)

def nmapCompleteScanProcess(host, port_list):
    try:
        DefaultConfigTCP = '-p ' + port_list + ' -O -sT -sV -sC -A -T5'
        start_time = time.time()
        nmTCP = nmap.PortScanner()
        document = nmTCP.scan(hosts = host, arguments = DefaultConfigTCP)

        for host in nmTCP.all_hosts():
            print('[*] ')
            print('[*] Details:')
            print('[*] ----------------------------------------------------')
            print('[*] Hostname : %s' % (nmTCP[host].hostname()))
            print('[*] State : %s' % nmTCP[host].state())
            print('[*] OS guess: %s\t, accuracy: %s\t' % (nmTCP[host]['osmatch'][0]['name'], nmTCP[host]['osmatch'][0]['accuracy']))
            try:
                print('[*] Last boot: %s' % nmTCP[host]['uptime']['lastboot'])
            except Exception as err:
                print('[*] Exception while executing nmap: %s' % err)
            for proto in nmTCP[host].all_protocols():
                print('[*] ----------------------------------------------------')
                print('[*] Protocol : %s' % proto)

                lport = nmTCP[host][proto].keys()
                for port in lport:
                    print ('[*] port : %s\tstate : %s\tservice : %s\t\tproduct : %s %s %s' % 
                        (port, nmTCP[host][proto][port]['state'], nmTCP[host][proto][port]['name'], nmTCP[host][proto][port]['product'], nmTCP[host][proto][port]['version'], nmTCP[host][proto][port]['extrainfo']))
            
        stop_time = time.time()
        execution_time = stop_time - start_time
        print('[*] Nmap complete scan execution time: %.4f' % execution_time + ' s')
        return document
    except Exception as err:
        print('[*] Exception while executing nmap: %s' % err)

def nmapCustomScanProcess(host, custom_argument, port):
    try:
        DefaultConfigTCP = '-p' + str(port) + ' ' + custom_argument
        return_dict = {
            'nmap': DefaultConfigTCP,
            'info': {}
        }
        return_dict['info']['port'] = port
        nmTCP = nmap.PortScanner()
        document = nmTCP.scan(hosts = host, arguments = DefaultConfigTCP)

        for host in nmTCP.all_hosts():
            for proto in nmTCP[host].all_protocols():
                lport = nmTCP[host][proto].keys()
                for port in lport:
                    lkeys = nmTCP[host][proto][port].keys()
                    for key in lkeys:
                        return_dict['info'][key] = nmTCP[host][proto][port][key]

        return document, return_dict    
    except Exception as err:
        print('[*] Exception while executing nmap: %s' % err)