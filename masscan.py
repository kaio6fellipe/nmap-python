import masscan
import logging
from rich.console import Console
import time
import netifaces as ni
import os
import nmap as python_nmap

def get_interface_ip(interface):
    try:
        src_ip = ni.ifaddresses(interface)[ni.AF_INET][0]['addr']
        return src_ip
    except Exception as err:
        print('[*] Exception while getting interface ip: %s' % err)

def valid_route(host):
    try:
        interfaces = ni.interfaces()
        for interface in interfaces:
            with DisableLogger():
                response = os.system("ping -c 1 -I " + interface + " " + host + ">/dev/null 2>&1")
            if response == 0:
                return get_interface_ip(interface)
    except Exception as err:
        print('[*] Exception while validating route: %s' % err)

class DisableLogger():
    def __enter__(self):
       logging.disable(logging.CRITICAL)
    def __exit__(self, exit_type, exit_value, exit_traceback):
       logging.disable(logging.NOTSET)

def masscanScanProcess(host):
    try:
        port_list = []
        start_time = time.time()
        src_ip = valid_route(host)
        scan = masscan.PortScanner()
        with DisableLogger():
            document = scan.scan(host, arguments='--max-rate 1000 --adapter-ip ' + str(src_ip))

        print('[*] ')
        print('[*] MasScan:')
        print('[*] ----------------------------------------------------')
        print("[*] IP: ", host)
        print("[*] Masscan version:", scan.masscan_version)
        for proto in document['scan'][str(host)]:
            print('[*] Protocol : %s' % proto)
            lport = document['scan'][str(host)][proto].keys()
            for port in lport:
                print('[*] port : %s\tstate : %s\t'% (port, document['scan'][str(host)][proto][port]['state']))
                port_list.append(port)

        stop_time = time.time()
        execution_time = stop_time - start_time
        new_port_list = str(port_list)[1:-1]
        print('[*] MasScan execution time: %.4f' % execution_time + ' s')
        python_nmap.func_nmapCompleteScan(host, new_port_list.replace(' ', ''))

    except Exception as err:
        print('[*] ')
        print('[*] Exception while executing masscan: %s' % err)
        python_nmap.func_nmapFastScanProcess(host)

def masscanScan(host, **kwargs):
    console = Console()
    with console.status("[bold]MasScan and Nmap working...") as status:
        masscanScanProcess(host)