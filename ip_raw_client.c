#include <time.h>
#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

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

void arrcat (u_char *result, u_char *buff, int from, int how_much) {
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
    const int bool_on = 1;
    u_short identificator = 1, check_sum = 0;
    int i = 0, bytes = 0, socket_fd = 0, sa_in_len = 0;
    int total_length = 0, offset_to_udp = 0, ip_ver_hdr_len = 0;
    char my_ip[] = "192.168.0.2", server_ip[] = "192.168.0.3";
    u_char message[] = "Kon'nichiwa from Client"; //23 bytes
    u_char *raw_buf = NULL;
    u_char buf_for_recv[100];
    struct sockaddr_in server_info, src_info;
    int server_port = 8080;
    int my_port = 1234;
    struct ip_header *ip_hdr = NULL;
    struct udp_header *udp_hdr = NULL;

    sa_in_len = sizeof(server_info);
    memset(&server_info, 0, sa_in_len);

    if (inet_aton(server_ip, (struct in_addr *)&server_info.sin_addr) == 0) {
	printf("Address of server is invalid!\n");
	return 0;
    }

    socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (socket_fd < 0) {
	perror("error in function socket()!");
	return 0;
    }

    if (setsockopt(socket_fd, IPPROTO_IP, IP_HDRINCL, &bool_on, sizeof(bool_on)) < 0) {
	perror("error in function setsockopt()");
	return 0;
    }

    server_info.sin_family = AF_INET;
    server_info.sin_port = htons(server_port);


    total_length = IP_HDR_LEN_WO_OPT + UDP_HDR_LEN + sizeof(message);
    raw_buf = calloc((total_length), sizeof(char));
    ip_hdr  = (struct ip_header *)raw_buf;
    ip_ver_hdr_len = IPV4;
    ip_ver_hdr_len <<= 4;
    ip_ver_hdr_len += (IP_HDR_LEN_WO_OPT / WORD_LEN_BYTES);
    ip_hdr->ver_hdr_len = ip_ver_hdr_len;
    ip_hdr->tos = 0;
    ip_hdr->pack_len = htons(total_length);
    printf("Total Length: %d (%d)\n", total_length, htons(total_length));
    ip_hdr->ident = htons(identificator);
    ip_hdr->flags_offset = htons(0); //don't fragment = 0, other bits = 0
    ip_hdr->ttl = 64;
    ip_hdr->protocol = 17;
    ip_hdr->hdr_chck_sum = htons(0);
    if (inet_aton(server_ip, &ip_hdr->dest_ip) == 0) {
	printf("Address of dest_ip is invalid!\n");
	return 0;
    }
    if (inet_aton(my_ip, &ip_hdr->src_ip) == 0) {
	printf("Address of src_ip is invalid!\n");
	return 0;
    }
    check_sum = crc16((u_short *)ip_hdr, IP_HDR_LEN_WO_OPT / 2);
    ip_hdr->hdr_chck_sum = check_sum; //already networked

    udp_hdr = (struct udp_header *)(raw_buf + IP_HDR_LEN_WO_OPT);
    udp_hdr->src_port = htons(my_port);
    udp_hdr->dest_port = htons(server_port);
    udp_hdr->length = htons(UDP_HDR_LEN + sizeof(message));
    udp_hdr->chck_sum = 0;

    arrcat(raw_buf, message, IP_HDR_LEN_WO_OPT + UDP_HDR_LEN, sizeof(message));
    printf("buffer\n");
    for (i = 0; i < IP_HDR_LEN_WO_OPT; i++) {
	printf("%d ", raw_buf[i]);
    }
    printf("\nsame in hex\n");
    for (i = 0; i < IP_HDR_LEN_WO_OPT; i++) {
	printf("%x ", raw_buf[i]);
    }
    printf("\n");
    for (i = IP_HDR_LEN_WO_OPT; i < IP_HDR_LEN_WO_OPT + UDP_HDR_LEN; i++) {
	printf("%d ", raw_buf[i]);
    }
    printf("\n");
    for (i = IP_HDR_LEN_WO_OPT + UDP_HDR_LEN; i < total_length; i++) {
	printf("%c", raw_buf[i]);
    }
    printf("\n");

    bytes = sendto(socket_fd, raw_buf, total_length, 0, (struct sockaddr *)&server_info, sa_in_len);
    if (bytes <= 0) {
	printf("error in function sendto(), sended %d bytes!\n", bytes);
    } else {
	printf("CLIENT: sended %d bytes to server(%s:%d)\n", bytes,
		    inet_ntoa(server_info.sin_addr), ntohs(server_info.sin_port));
    }
    while (1) {
	bytes = recvfrom(socket_fd, buf_for_recv, 100, 0, (struct sockaddr *)&src_info, (socklen_t *)&sa_in_len);
	if (bytes < 0) {
	    printf("error in function recvfrom(), received %d bytes!\n", bytes);
	} else {
	    ip_hdr = (struct ip_header *)buf_for_recv;
	    offset_to_udp = (ip_hdr->ver_hdr_len & GET_HALF_OF_BYTE) * WORD_LEN_BYTES;
	    udp_hdr =  (struct udp_header *)(buf_for_recv + offset_to_udp);
	    printf("check port %d...", ntohs(udp_hdr->dest_port));
	    if (my_port == ntohs(udp_hdr->dest_port)) {
	        printf("yes\nCLIENT: receiveded %d bytes from server (%s:%d) \n",
			    bytes, inet_ntoa(src_info.sin_addr), ntohs(src_info.sin_port));
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
    close(socket_fd);
    return 0;
}