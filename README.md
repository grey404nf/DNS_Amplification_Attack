# DNS Amplification Attack
DNS Amplification DDoS Attack in C++

Amplification attacks are used to magnify the bandwidth that is sent to a victim. This is typically done through publicly accessible DNS servers that are used to cause congestion on the target system using DNS response traffic. Many services can be exploited to act as reflectors, some harder to block than others.

# Run
```
$ cd src/DNS_Amplification_Attack/
$ ./dns_amp <Victim_IP> <UDP_Source_Port> <DNS_Server_IP>
```
