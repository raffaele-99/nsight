# nsight

vibe-coded tool that draws basic insights from nmap output.

Basically I always forget to note when a box is running SMB, because it sits on multiple ports. So this is an AI generated tool that read nmap output and point this out for me. Only works for TCP scans.

## usage

Just feed it an nmap file and it will return what it's identified, for example,

```
$ cat top-1000-tcp.nmap
# Nmap 7.95 scan initiated Thu Jun  5 20:34:01 2025 as: /usr/lib/nmap/nmap --privileged -oN top-1000-tcp.nmap -Pn 192.168.226.141
Nmap scan report for 192.168.226.141
Host is up (0.12s latency).
Not shown: 992 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
81/tcp   open  hosts2-ns
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3306/tcp open  mysql
5985/tcp open  wsman

# Nmap done at Thu Jun  5 20:34:10 2025 -- 1 IP address (1 host up) scanned in 9.41 seconds

$ nsight top-1000-tcp.nmap

▶ Possible SMB / NetBIOS file share detected: Required ports 139, 445 are present

▶ Possible Windows RPC services (EPM + dynamic RPC) detected: Required ports 135 are present 

```


