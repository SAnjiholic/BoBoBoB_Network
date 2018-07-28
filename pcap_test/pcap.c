#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include "libnet.h"

void my_mac(uint8_t mac[]){
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);}

void my_ip(uint8_t ip[]){
	printf("%d.%d.%d.%d\n",ip[0],ip[1],ip[2],ip[3]);}

void hex_print(const char *p_buf){
	printf("Http data : ");
	for(int cnt = 0; cnt <16; cnt++){
	printf("%02x ",p_buf[cnt]);
	}
	printf("\n");
}


int main(int argc, char *argv[]) {
	int pktCnt=0;
	int i=0;
	int j=0;
	int devnum;
	int res;
	struct pcap_pkthdr *header;
	struct libnet_ethernet_hdr *eth;
	struct libnet_ipv4_hdr *ip;
	struct libnet_arp_hdr *arp;
	struct libnet_tcp_hdr *tcp;
	struct libnet_udp_hdr *udp;
	pcap_if_t *alldevs;
	pcap_if_t *dev;
	pcap_t *pcap;
	const u_char *data;
	char *err;
	char ip_buf[16];
	if (pcap_findalldevs(&alldevs, err) == -1){
		fprintf(stderr,"Not find devs: %s\n", err);
		exit(1);
	}
	for(dev = alldevs; dev; dev = dev->next){
		printf("%d. %s\n", ++j, dev->name);
	}
	if(j==0){
		printf("Not found Interfaces");
		return -1;}
	printf("Enter interface number (1-%d):",j);
	scanf("%d", &devnum);
	if (devnum < 1 || devnum > j ){
		printf("\nNo.%d is wrong number", devnum);
		pcap_freealldevs(alldevs);
		return -1;}
	for (dev = alldevs, j = 0; j< devnum-1; dev = dev->next,i++);
	if ((pcap = pcap_open_live(dev->name,
					65536,
					0,
					1000,
					err)) == NULL){
		fprintf(stderr, "\n%s open fail :( \n", dev->name);
		pcap_freealldevs(alldevs);
		return -1;}
	printf("\nListening on %s\n", dev->description);
	while((res = pcap_next_ex(pcap, &header, &data)) >=0){
		if(res == 0) continue;
		eth = (struct libnet_ethernet_hdr *) data;
		printf("\nPcaket No .%i\n",++pktCnt);
		printf("Packet size : %d bytes\n",header->len);

		if((ntohs(eth->ether_type)) == ETHERTYPE_IP){//IP
			ip = (struct libnet_ipv4_hdr *)(data + sizeof(struct libnet_ethernet_hdr));
			printf("Dst Mac : "); my_mac(eth->ether_dhost);
			printf("Src Mac : "); my_mac(eth->ether_shost);
			printf("Src IP : "); my_ip(ip->ip_src);
			printf("Dst IP : "); my_ip(ip->ip_dst); 
			if((ip->ip_p)== IPPROTO_UDP){//UDP
				udp =(struct libnet_udp_hdr *)(data +sizeof(struct libnet_ethernet_hdr)+sizeof(struct libnet_ipv4_hdr));
				printf("Src Port : %d\n",ntohs(udp->uh_sport));
				printf("Dst Port : %d\n",ntohs(udp->uh_dport));
			}
			else if((ip->ip_p) == IPPROTO_TCP){//TCP
				tcp = (struct libnet_tcp_hdr *)(data + sizeof(struct libnet_ethernet_hdr)+sizeof(struct libnet_ipv4_hdr));
				printf("Src port : %d\n",ntohs(tcp->th_sport));
				printf("Dst Port : %d\n",ntohs(tcp->th_dport));
				if (ntohs(tcp->th_sport) == 80 || ntohs(tcp->th_dport) == 80 ){
					if(header->len != 66){
					int tcp_len = (tcp->th_off * 4) - 20;
					const char *http_data = (const char *)(data + sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr) + sizeof(struct libnet_tcp_hdr) + tcp_len);
					hex_print(http_data);
					}
				}
			}
		}
		else if((ntohs(eth->ether_type)) == ETHERTYPE_ARP){//ARP
			arp = (struct libnet_arp_hdr *)(data + sizeof(struct libnet_ethernet_hdr));
			printf("Sender Mac : "); my_mac(arp->s_mac);
			printf("Sender IP : "); my_ip(arp->s_ip);
			printf("Target Mac : "); my_mac(arp->t_mac);
			printf("Target IP : "); my_ip(arp->t_ip);
		}
	}
}
