<a href="https://kaio6fellipe.github.io/"><img src="./images/back-home.png" alt="Home Page" width="50" height="58" style="filter: grayscale(100%)"></a> 

# Information
> I end up wasting a lot of time doing long and detailed scans with nmap, but in the end they were neeeded.
>
> To get rid of this problem, I needed to be very accurate with what I was supposed to scan. A good way to speed up this process would be to extract a list of open ports and then scan these ports with the full scan.
>
> To do this, run masscan, get the list of open ports, and run a full scan with nmap. If masscan has a problem, run nmap's fast scan, get the list of open ports, and run a full scan later. See [Details](#details) and [Example](#example) to see how it works

# Configuration
Install some Python packages:
```shell
pip install netifaces
```
```shell
pip install python-nmap
```
```shell
pip install python-masscan
```
# Details

The [python_masscan.py](./python_masscan.py) file contains 1 usable function:
- masscanProcess
  - This function receives a string with the host IP or DNS
  - The scan will start executing this argument in masscan : --max-rate 1000 --adpter-ip (your ip)
  - When the scan is finished, some information will be displayed on the screen
  - This function will return the dictionary generated by the scan and a string containing all the open ports in the host separated with a comma

The [python_nmap.py](./python_nmap.py) file contains 3 usable functions:
- nmapFastScanProcess
- nmapCompleteScanProcess
- nmapCustomScanProcess

# Example

- Working on the example...

```python
# Some Python Example here
```
