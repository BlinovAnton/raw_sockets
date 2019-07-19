#include <time.h>
#include <errno.h>
#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <linux/if_packet.h>

#define IPV4 4
#define UDP_HDR_LEN 8
#define GET_HALF_OF_BYTE 15
#define WORD_LEN_BYTES 4
#define IP_HDR_LEN_WO_OPT 20
#define MAX_U_SHORT 65535
#define MIN_U_SHORT 1

struct udp_header {
    u_short src_port;
    u_short dest_port;
    u_short length;
    u_short chck_sum;
};

struct ip_header {
    u_char ver_hdr_len;
    u_char tos;
    u_short pack_len;
    u_short ident;
    u_short flags_offset;
    u_char ttl;
    u_char protocol;
    u_short hdr_chck_sum;
    struct in_addr src_ip;
    struct in_addr dest_ip;
};

void arrcat (u_char *result, char *buff, int from, int how_much) {
    int i = from, j = 0;
    for (; i < from + how_much; i++, j++) {
	result[i] = (u_char)buff[j];
    }
}

u_short crc16 (u_short* pcBlock, u_int len) {
    u_long sum = 0;

    while (len > 1) {
	sum += *pcBlock++;
	len -= 2;
    }

    if(len > 0)
	sum += ((*pcBlock)&htons(0xFF00));

    while (sum>>16) {
	sum = (sum & 0xffff) + (sum >> 16);
    }

    sum = ~sum;
    return ((u_short)sum);
}

void crc16_ip (struct ip_header* ip_hdr) {
    ip_hdr->hdr_chck_sum = 0;
    ip_hdr->hdr_chck_sum = crc16((u_short*)ip_hdr, (ip_hdr->ver_hdr_len & 7) << 2);

}

int main () {
    int i, bytes, server_socket_fd, ip_ver_hdr_len;
    int total_length;
    unsigned int ifindex = 0;
    char send_address[] = "192.168.0.2";
    char recv_address[] = "192.168.0.255";
    char send_intf[] = "eth1";
    char message[] = "Zdravstvuyte from server\n"; //24 bytes + \0
    u_char *raw_buf;
    struct sockaddr_ll server_info;
    struct ifreq if_req_mac;
    int server_port = 7777;
    int client_port = 7778;
    printf("Client port %d (%d)\n", client_port, htons(client_port));
    struct ethhdr *eth_hdr;
    struct ip_header *ip_hdr;
    struct udp_header *udp_hdr;
    const int bool_on_off = 1;

    memset(&server_info, 0, sizeof(server_info));
    memset(&if_req_mac, 0, sizeof(if_req_mac));

    server_socket_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (server_socket_fd < 0) {
	perror("error in function socket()!");
	return 0;
    }

    ifindex = if_nametoindex(send_intf); //ioctl is shit!
    server_info.sll_family = AF_PACKET;
    server_info.sll_protocol = htons(ETH_P_ALL);
    server_info.sll_ifindex = ifindex;
    server_info.sll_halen = ETH_ALEN;

    memset(&if_req_mac, 0, sizeof(if_req_mac));
    sprintf(if_req_mac.ifr_name, "%s", send_intf);
    if_req_mac.ifr_ifindex = ifindex;
    if (ioctl(server_socket_fd, SIOCGIFHWADDR, if_req_mac.ifr_name) == -1) {
	perror("error in func ioctl(SIOCGIFHWADDR)");
	return 0;
    }
    for (i = 0; i < ETH_ALEN; i++) {
	server_info.sll_addr[i] = ((u_char *)&if_req_mac.ifr_hwaddr.sa_data)[i];
	printf("%.2x ", server_info.sll_addr[i]);
    }
    printf("\n");

    total_length = IP_HDR_LEN_WO_OPT + UDP_HDR_LEN + sizeof(message);
    raw_buf = calloc((total_length + ETH_HLEN), sizeof(char));
    eth_hdr = (struct ethhdr *)raw_buf;
    for (i = 0; i < ETH_ALEN; i++) {
	eth_hdr->h_dest[i] = 0xff;
    }
    printf("own mac: ");
    for (i = 0; i < ETH_ALEN; i++) {
	eth_hdr->h_source[i] = server_info.sll_addr[i];
	printf("0x%.2x ", eth_hdr->h_source[i]);
    }
    printf("\n");
    eth_hdr->h_proto = htons(ETH_P_IP);

    ip_hdr = (struct ip_header *)(raw_buf + ETH_HLEN);
    ip_ver_hdr_len = IPV4;
    ip_ver_hdr_len <<= 4;
    ip_ver_hdr_len += (IP_HDR_LEN_WO_OPT / WORD_LEN_BYTES);
    ip_hdr->ver_hdr_len = ip_ver_hdr_len;
    ip_hdr->tos = 0;
    ip_hdr->pack_len = htons(total_length);
    ip_hdr->ident = htons(16401);
    ip_hdr->flags_offset = htons(16384); //flags=0x02 offset=0
    ip_hdr->ttl = 64;
    ip_hdr->protocol = 17;
    ip_hdr->hdr_chck_sum = htons(0);
    if (inet_aton(recv_address, &ip_hdr->dest_ip) == 0) {
	printf("Address of dest_ip is invalid!\n");
	return 0;
    }
    if (inet_aton(send_address, &ip_hdr->src_ip) == 0) {
	printf("Address of src_ip is invalid!\n");
	return 0;
    }

    crc16_ip(ip_hdr);

    udp_hdr = (struct udp_header *)(raw_buf + IP_HDR_LEN_WO_OPT + ETH_HLEN);
    udp_hdr->src_port = htons(client_port);
    udp_hdr->dest_port = htons(server_port);
    udp_hdr->length = htons(UDP_HDR_LEN + sizeof(message));
    udp_hdr->chck_sum = htons(0);

    arrcat(raw_buf, message, ETH_HLEN + IP_HDR_LEN_WO_OPT + UDP_HDR_LEN, sizeof(message));
    printf("buffer\n");
    for (i = 0; i < ETH_ALEN; i++) {
	printf("0x%.2x ", raw_buf[i]);
    }
    printf(" | ");
    for (i = ETH_ALEN; i < 2 * ETH_ALEN; i++) {
	printf("0x%.2x ", raw_buf[i]);
    }
    printf(" | ");
    for (i = 2 * ETH_ALEN; i < ETH_HLEN; i++) {
	printf("0x%.2x ", raw_buf[i]);
    }
    printf("\ndec IP_hdr: ");
    for (i = ETH_HLEN; i < ETH_HLEN + IP_HDR_LEN_WO_OPT; i++) {
	printf("%u ", raw_buf[i]);
    }
    printf("\nhex IP_hdr: ");
    for (i = ETH_HLEN; i < ETH_HLEN + IP_HDR_LEN_WO_OPT; i++) {
	printf("0x%.2x ", raw_buf[i]);
    }
    printf("\ndec UDP_hdr: ");
    for (i = ETH_HLEN + IP_HDR_LEN_WO_OPT; i < ETH_HLEN + IP_HDR_LEN_WO_OPT + UDP_HDR_LEN; i++) {
	printf("%u ", raw_buf[i]);
    }
    printf("\nhex UDP_hdr: ");
    for (i = ETH_HLEN + IP_HDR_LEN_WO_OPT; i < ETH_HLEN + IP_HDR_LEN_WO_OPT + UDP_HDR_LEN; i++) {
	printf("0x%.2x ", raw_buf[i]);
    }
    printf("\n");
    for (i = ETH_HLEN + IP_HDR_LEN_WO_OPT + UDP_HDR_LEN; i < ETH_HLEN + total_length; i++) {
	printf("%c", raw_buf[i]);
    }
    printf("\n");
while (1) {
    bytes = sendto(server_socket_fd, raw_buf, ETH_HLEN + total_length, 0, (struct sockaddr *)&server_info, sizeof(server_info));
    if (bytes <= 0) {
	printf("error #%d in function sendto(), sended %d bytes!\n", errno, bytes);
	perror("fuck'd up");
    } else {
	printf("CLIENT: sended %d bytes to server ()\n", bytes);
    }
    sleep(2);
}
    close(server_socket_fd);
    return 0;
}