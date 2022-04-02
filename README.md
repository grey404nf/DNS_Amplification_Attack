# DNS Amplification Attack
DNS Amplification DDoS Attack in C++

Amplification attacks are used to magnify the bandwidth that is sent to a victim. This is typically done through publicly accessible DNS servers that are used to cause congestion on the target system using DNS response traffic. Many services can be exploited to act as reflectors, some harder to block than others.

In brief, we used the DNS ANY query type and expanded the size of DNS packets by the use of EDNS0. \
The ANY query, which will retrieve all records available for a domain name, is often used in the DoS Attack. \
The EDNS0, which is a specification for expanding the size of several parameters of the DNS protocol, has no 512 bytes UDP size limit.

# Run
```
$ cd src/DNS_Amplification_Attack/
$ sudo ./dns_amp <Victim_IP> <UDP_Source_Port> <DNS_Server_IP>
```
