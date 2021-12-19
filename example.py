import python_masscan
import python_nmap

host = '192.168.0.120'

try:
    scan_ms, port_list_ms = python_masscan.masscanProcess(host)
    complete_scan = python_nmap.nmapCompleteScanProcess(host, port_list_ms)
except:
    scan_nm, port_list_nm = python_nmap.nmapFastScanProcess(host)
    complete_scan = python_nmap.nmapCompleteScanProcess(host, port_list_nm)

print(complete_scan)