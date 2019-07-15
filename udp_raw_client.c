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

#define UDP_HDR_LEN 8
#define GET_HALF_OF_BYTE 15
#define WORD_LEN_BYTES 4

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
    struct in_addr dest_ip;
    struct in_addr src_ip;
};

void arrcat (u_char *result, u_char *buff, int from, int how_much) {
    int i = from, j = 0;
    for (; i < from + how_much; i++, j++) {
	result[i] = buff[j];
    }
}

int main () {
    srand(time(NULL));
    int i = 0, bytes = 0, socket_fd = 0, sain_len = 0;
    char server_address[] = "192.168.0.3";
    u_char message[] = "Kon'nichiwa from Client\n";
    u_char *raw_buf;
    char buf_for_recv[100];
    struct sockaddr_in server_info, src_info;
    int server_port = 8080, my_port = 1234, offset_to_udp = 0;
    struct ip_header *ip_hdr;
    struct udp_header *udp_hdr;

    sain_len = sizeof(struct sockaddr_in);
    memset(&server_info, 0, sain_len);

    if (inet_aton(server_address, (struct in_addr *)&server_info.sin_addr) == 0) {
	printf("Address of server is invalid!\n");
	return 0;
    }

    socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (socket_fd < 0) {
	perror("error in function socket()!");
	return 0;
    }

    server_info.sin_family = AF_INET;
    server_info.sin_port = htons(server_port);

    raw_buf = calloc((UDP_HDR_LEN + sizeof(message)), sizeof(char));
    udp_hdr =  (struct udp_header *)raw_buf;
    udp_hdr->src_port = htons(my_port);
    udp_hdr->dest_port = htons(server_port);
    udp_hdr->length = htons(UDP_HDR_LEN + sizeof(message));
    udp_hdr->chck_sum = 0;
    arrcat(raw_buf, message, UDP_HDR_LEN, sizeof(message));
    printf("buffer\n");
    for (i = 0; i < UDP_HDR_LEN; i++) {
	printf("%d ", raw_buf[i]);
    }
    for (i = UDP_HDR_LEN; i < UDP_HDR_LEN + sizeof(message); i++) {
	printf("%c", raw_buf[i]);
    }
    printf("\n");

    bytes = sendto(socket_fd, raw_buf, UDP_HDR_LEN + sizeof(message), 0, (struct sockaddr *)&server_info, sain_len);
    if (bytes <= 0) {
	printf("error in function sendto(), sended %d bytes!\n", bytes);
    } else {
	printf("CLIENT: sended %d bytes to server (%s:%d)\n", bytes,
		    inet_ntoa(server_info.sin_addr), ntohs(server_info.sin_port));
    }
    while (1) {
	bytes = recvfrom(socket_fd, buf_for_recv, 100, 0, (struct sockaddr *)&src_info, (socklen_t *)&sain_len);
	if (bytes < 0) {
	    printf("error in function recvfrom(), received %d bytes!\n", bytes);
	} else {
	    ip_hdr = (struct ip_header *)buf_for_recv;
	    offset_to_udp = (ip_hdr->ver_hdr_len & GET_HALF_OF_BYTE) * WORD_LEN_BYTES;
	    udp_hdr =  (struct udp_header *)(buf_for_recv + offset_to_udp);
	    printf("check port %d...", ntohs(udp_hdr->dest_port));
	    if (my_port == ntohs(udp_hdr->dest_port)) {
	        printf("yes\nCLIENT: receiveded %d bytes from server (%s:%d): \n", bytes,
			    inet_ntoa(src_info.sin_addr), ntohs(src_info.sin_port));
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