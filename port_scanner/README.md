# Simple Port Scanner
_Created by Jackson Howe on 20 Feb 2021_


## Getting Started
The port scanner can be run as a regular Python script. Requires Python3. Also must be run as a privileged user,
i.e. run:
```
sudo python3 port_scanner.py [args...]
```

Run `port_scanner.py --help` to see the following documentation:
```
usage: port_scanner.py [-h] (--host HOST | --hosts HOSTS | --input INPUT) [--port PORT [PORT ...]] [--type {syn,ack,udp}] [--timeout TIMEOUT] [--output OUTPUT]

A simple port scanning utility

optional arguments:
  -h, --help            show this help message and exit
  --host HOST           Single host to scan
  --hosts HOSTS         Range and subnet mask to scan
  --input INPUT         File with list of hosts to scan (1 host per line)
  --port PORT [PORT ...]
                        Port(s) to scan (provide at least 1)
  --type {syn,ack,udp}  The protocol and scan type
  --timeout TIMEOUT     Connection timeout in seconds
  --output OUTPUT       HTML output file
```


## Usage & Features
* Hosts can be provided in one of three ways. Each host will be scanned by the script.
    1. `--host [ip]` a single IP address
    2. `--hosts [ip/subnet]` a range of IP addresses
    3. `--input [in.txt]` a txt file containing a newline-separated list if hosts

* One or more ports can be specified in list style, i.e.: `--port 22 80 443`

* There are three supported scans:
    1. `--type syn` a basic TCP SYN scan which sends a TCP SYN packet - stealthy because the TCP handshake is never completed.
    2. `--type ack` a TCP ACK scan which can be used to determine whether a port is filtered/unfiltered.
    3. `--type udp` a UDP scan
    
* Use `--timeout seconds` to specify the timeout interval per scan, in seconds. Default is 2 seconds.

* The output is printed to the console by default. An HTML report can be generated instead by specifying `--output out.html`.
Console results appear as follows:
```
192.168.1.1:22/TCP-SYN Closed
192.168.1.1:53/TCP-SYN Open
192.168.1.1:80/TCP-SYN Open
192.168.1.1:443/TCP-SYN Open
```

* Specifying multiple hosts and ports will run a scan of type `type` on each host/port combination.


### Example
```
sudo python3 port_scanner.py --type syn --hosts 192.168.1.0/24 --port 22 80 443 --output out.html --timeout 1
```
Runs a basic TCP SYN scan on ports 22, 80, and 443 on all the hosts in the 192.168.1.0/24 range. Each scan is given 1
second to complete. The results are saved to out.html.