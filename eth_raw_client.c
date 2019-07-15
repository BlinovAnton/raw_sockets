#include <time.h>
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
#define MAC_ADDR_LEN 6
#define ETH_HDR_LEN 14

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

struct eth_header {
    u_char dest[MAC_ADDR_LEN];
    u_char src[MAC_ADDR_LEN];
    u_short proto_type;
};

void arrcat (unsigned char *result, char *buff, int from, int how_much) {
    int i = from, j = 0;
    for (; i < from + how_much; i++, j++) {
	result[i] = buff[j];
    }
}

u_short crc16 (u_short *pcBlock, int len) {
    u_long sum;
    for (sum = 0; len > 0; len--) {
	sum += *pcBlock++;
    }
    sum = (sum >> 16) + (sum &0xffff);
    sum += (sum >> 16);
    return (u_short)(~sum);
}

int main () {
    srand(time(NULL));
    u_short identificator, check_sum;
    int i = 0, bytes = 0, offset_to_udp = 0, my_socket_fd = 0;
    int total_length = 0, ip_ver_hdr_len = 0;
    char my_address[] = "192.168.0.2";
    char recv_ip[] = "192.168.0.3";
    char *my_intf = "eth1";
    char message[] = "Kon'nichiwa from Client"; //23 bytes
    unsigned char *raw_buf;
    u_char buf_for_recv[100];
    struct sockaddr_ll my_info;
    struct ifreq if_req_mac;
    int recv_port = 8080, my_port = 1234, ifindex = 0;
    printf("Dest port %d (%d)\n", recv_port, htons(recv_port));
    struct eth_header *eth_hdr;
    struct ip_header *ip_hdr;
    struct udp_header *udp_hdr;
    unsigned char dest_mac[MAC_ADDR_LEN] = {0x8, 0x0, 0x27, 0x1a, 0xc8, 0xe5};

    memset(&my_info, 0, sizeof(my_info));
    memset(&if_req_mac, 0, sizeof(if_req_mac));

    my_socket_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (my_socket_fd < 0) {
	perror("error in function socket()!");
	return 0;
    }

    ifindex = if_nametoindex(my_intf);
    my_info.sll_family = AF_PACKET;
    my_info.sll_protocol = htons(ETH_P_ALL);
    my_info.sll_ifindex = ifindex;
    my_info.sll_halen = MAC_ADDR_LEN;

    memset(&if_req_mac, 0, sizeof(if_req_mac));
    sprintf(if_req_mac.ifr_name, "%s", my_intf);
    if_req_mac.ifr_ifindex = ifindex;
    if (ioctl(my_socket_fd, SIOCGIFHWADDR, if_req_mac.ifr_name) == -1) {
	perror("error in func ioctl(SIOCGIFHWADDR)");
	return 0;
    }
    printf("my intf: %s\n", if_req_mac.ifr_name);
    for (i = 0; i < MAC_ADDR_LEN; i++) {
	my_info.sll_addr[i] = ((u_char *)&if_req_mac.ifr_hwaddr.sa_data)[i];
    }

    total_length = IP_HDR_LEN_WO_OPT + UDP_HDR_LEN + sizeof(message);
    raw_buf = calloc((total_length + ETH_HDR_LEN), sizeof(char));
    eth_hdr = (struct eth_header *)raw_buf;
    printf("dest mac: ");
    for (i = 0; i < MAC_ADDR_LEN; i++) {
	eth_hdr->dest[i] = dest_mac[i];
	printf("%.2x ", eth_hdr->dest[i]);
    }
    printf("\nmy mac: ");
    for (i = 0; i < MAC_ADDR_LEN; i++) {
	eth_hdr->src[i] = my_info.sll_addr[i];
	printf("%.2x ", eth_hdr->src[i]);
    }
    printf("\n");
    eth_hdr->proto_type = htons(0x0800);

    ip_hdr  = (struct ip_header *)(raw_buf + ETH_HDR_LEN);
    ip_ver_hdr_len = IPV4;
    ip_ver_hdr_len <<= 4;
    ip_ver_hdr_len += (IP_HDR_LEN_WO_OPT / WORD_LEN_BYTES);
    ip_hdr->ver_hdr_len = ip_ver_hdr_len;
    ip_hdr->tos = 0;
    ip_hdr->pack_len = htons(total_length);
    printf("Total Length: %d (%d)\n", total_length, htons(total_length));
    identificator = 1;
    ip_hdr->ident = htons(identificator);
    ip_hdr->flags_offset = htons(0); //don't fragment = 0, other bits = 0
    ip_hdr->ttl = 64;
    ip_hdr->protocol = 17;
    ip_hdr->hdr_chck_sum = htons(0);
    if (inet_aton(recv_ip, &ip_hdr->dest_ip) == 0) {
	printf("Address of dest_ip is invalid!\n");
	return 0;
    }
    if (inet_aton(my_address, &ip_hdr->src_ip) == 0) {
	printf("Address of src_ip is invalid!\n");
	return 0;
    }
    //check_sum = crc16(raw_buf + ETH_HDR_LEN, IP_HDR_LEN_WO_OPT);
    check_sum = crc16((u_short *)ip_hdr, IP_HDR_LEN_WO_OPT / 2);
    ip_hdr->hdr_chck_sum = check_sum;

    udp_hdr = (struct udp_header *)(raw_buf + IP_HDR_LEN_WO_OPT + ETH_HDR_LEN);
    udp_hdr->src_port = htons(my_port);
    udp_hdr->dest_port = htons(recv_port);
    udp_hdr->length = htons(UDP_HDR_LEN + sizeof(message));
    udp_hdr->chck_sum = 0;

    arrcat(raw_buf, message, ETH_HDR_LEN + IP_HDR_LEN_WO_OPT + UDP_HDR_LEN, sizeof(message));
    printf("buffer\n");
    for (i = 0; i < MAC_ADDR_LEN; i++) {
	printf("%.2x ", raw_buf[i]);
    }
    printf(" | ");
    for (i = MAC_ADDR_LEN; i < 2 * MAC_ADDR_LEN; i++) {
	printf("%.2x ", raw_buf[i]);
    }
    printf(" | ");
    for (i = 2 * MAC_ADDR_LEN; i < ETH_HDR_LEN; i++) {
	printf("%.2d ", raw_buf[i]);
    }
    printf("\n");
    for (i = ETH_HDR_LEN; i < ETH_HDR_LEN + IP_HDR_LEN_WO_OPT; i++) {
	printf("%u ", raw_buf[i]);
    }
    printf("\n");
    for (i = ETH_HDR_LEN; i < ETH_HDR_LEN + IP_HDR_LEN_WO_OPT; i++) {
	printf("%x ", raw_buf[i]);
    }
    printf("\n");
    for (i = ETH_HDR_LEN + IP_HDR_LEN_WO_OPT; i < ETH_HDR_LEN + IP_HDR_LEN_WO_OPT + UDP_HDR_LEN; i++) {
	printf("%u ", raw_buf[i]);
    }
    printf("\n");
    for (i = ETH_HDR_LEN + IP_HDR_LEN_WO_OPT + UDP_HDR_LEN; i < ETH_HDR_LEN + total_length; i++) {
	printf("%c", raw_buf[i]);
    }
    printf("\n");

    bytes = sendto(my_socket_fd, raw_buf, ETH_HDR_LEN + total_length, 0, (struct sockaddr *)&my_info, sizeof(my_info));
    if (bytes <= 0) {
	printf("error in function sendto(), sended %d bytes!\n", bytes);
	return 0;
    } else {
	printf("CLIENT: sended %d bytes to server ()\n", bytes);
    }
    while (1) {
	bytes = recvfrom(my_socket_fd, buf_for_recv, 100, 0, NULL, NULL);
	if (bytes < 0) {
	    printf("error in function recvfrom(), received %d bytes!\n", bytes);
	    return 0;
	} else {
	    eth_hdr = (struct eth_header *)buf_for_recv;
	    ip_hdr = (struct ip_header *)(buf_for_recv + ETH_HDR_LEN);
	    offset_to_udp = (ip_hdr->ver_hdr_len & GET_HALF_OF_BYTE) * WORD_LEN_BYTES + ETH_HDR_LEN;
	    udp_hdr = (struct udp_header *)(buf_for_recv + offset_to_udp);
	    if (my_port == ntohs(udp_hdr->dest_port)) {
	        printf("port %d\n", ntohs(udp_hdr->dest_port));
	        printf("CLIENT: receiveded %d bytes from server(): \n", bytes);
	        for (i = offset_to_udp + UDP_HDR_LEN; i < bytes; i++) {
		    if (isprint(buf_for_recv[i])) {
			printf("%c", buf_for_recv[i]);
		    } else {
			printf(". ");
		    }
		}
		printf("\n");
		break;
	    }
	    printf("no\n");
	}
    }
    close(my_socket_fd);
    return 0;
}