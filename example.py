import python_masscan
import python_nmap

# Setting the target
host = '192.168.0.120'

# Try, Except to execute masscan first, if it fails for some reason, execute nmap fast scan instead
try:
    # Extracting the dictionary and the list of ports from the masscan module
    scan_ms, port_list_ms = python_masscan.masscanProcess(host)
    # Extracting the dictionary from the nmap module, passing the port list from the masscan module
    complete_scan = python_nmap.nmapCompleteScanProcess(host, port_list_ms)
except:
    # Extracting the dicionary and the list os ports from the nmap module
    scan_nm, port_list_nm = python_nmap.nmapFastScanProcess(host)
    # Extracting the dictionary from the nmap module, passing the port list from the nmap module
    complete_scan = python_nmap.nmapCompleteScanProcess(host, port_list_nm)

# Printing the dictionary
print(complete_scan)