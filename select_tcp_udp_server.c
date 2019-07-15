#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <semaphore.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define FILE_EXIST 17
#define LISTEN_QUEUE 3
#define MAX_IP_LENGTH 15
#define COND_MSG_SIZE 100
#define CLEAN_ZOMB_FREQ 5

#define max(a, b) ((a > b) ? (a) : (b))

pid_t main_pid = 0;
sem_t *semka = NULL;
int start_pid_cer = 0, mmap_size = sizeof(int);
int shmfd = 0, *end_pid_cer = NULL;
int tcp_listen_fd = 0, tcp_accept_fd = 0, udp_socket = 0;
char *semaph_name = "semka_file";

void sigint_hand (int);

int main () {
    int i = 0, port = 8080, bytes = 0, status = 0;
    int  bind_res = 0, cli_struct_len = 0, select_res = 0;
    unsigned short tcp_port = 0, udp_port = 0, max_fd;
    struct sockaddr_in server_info, client_info;
    char buf_for_recv[COND_MSG_SIZE];
    char *server_ip = NULL, *client_ip = NULL;
    pid_t pid = 0;
    fd_set mask_of_read_fd;
    char message[] = "Alloha from server!";
    char *shmem_name = "shmem_file";
    char server_address[][MAX_IP_LENGTH] = {"192.168.0.2", "10.0.2.15", "127.0.0.1"};

    struct sigaction new_act, old_act;
    new_act.sa_handler = sigint_hand;
    sigemptyset(&new_act.sa_mask);
    new_act.sa_flags = 0;
    sigaction(SIGINT, NULL, &old_act);
    if (old_act.sa_handler != SIG_IGN) {
	sigaction(SIGINT, &new_act, NULL);
    }

    shmfd = shm_open(shmem_name, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
    if (shmfd == -1) {
	printf("shm_open() fault\n");
	perror(":::");
	goto error_in_parent;
    }

    if (ftruncate(shmfd, mmap_size) != 0) {
	printf("ftruncate() fault\n");
	perror(":::");
	goto error_in_parent;
    }

    end_pid_cer = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, shmfd, 0);
    if (end_pid_cer == MAP_FAILED) {
	printf("mmap() fault\n");
	perror(":::");
	goto error_in_parent;
    }
    /* fd opened by shm_open can be close after mmap() without any negative effects */
    close(shmfd);
    *end_pid_cer = 0;

    semka = sem_open(semaph_name, O_CREAT | O_EXCL, S_IRUSR | S_IWUSR, 1);
    if (semka == SEM_FAILED) {
	if (errno == FILE_EXIST) {
	    semka = sem_open(semaph_name, O_RDWR);
	}
	if (semka == SEM_FAILED) {
	    printf("sem_open() fault\n");
	    perror(":::");
	    goto error_in_parent;
	}
    }

    main_pid = getpid();
    printf("Original pid = %d\n", main_pid);
    memset(&server_info, 0, sizeof(server_info));

    tcp_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_listen_fd < 0) {
	printf("socket(tcp) fault\n");
	perror(":::");
	goto error_in_parent;
    }
    server_info.sin_family = AF_INET;
    server_info.sin_port = htons(port);

    for (i = 0; i < sizeof(server_address) / MAX_IP_LENGTH; i++) {
	if (inet_aton(server_address[i], (struct in_addr *)&server_info.sin_addr) == 0) {
	    printf("inet_aton() fault\n");
	    perror(":::");
	    goto error_in_parent;
	}
	printf("trying bind TCP server to %s:%d - ", server_address[i], ntohs(server_info.sin_port));
	bind_res = bind(tcp_listen_fd, (struct sockaddr *)&server_info, sizeof(server_info));
	if (bind_res < 0) {
	    printf("shit\n");
	    perror(":::");
	} else {
	    printf("OK binded\n");
	    if (listen(tcp_listen_fd, LISTEN_QUEUE) < 0) {
		printf("listen() fault\n");
		perror(":::");
		goto error_in_parent;
	    }
	    tcp_port = ntohs(server_info.sin_port);

	    //udp_socket
	    udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
	    if (udp_socket < 0) {
		printf("socket(UDP) fault\n");
		perror(":::");
		goto error_in_parent;
	    }
	    if (bind(udp_socket, (struct sockaddr *)&server_info, sizeof(server_info)) < 0) {
		printf("bind(UDP) fault\n");
		perror(":::");
		goto error_in_parent;
	    }
	    udp_port = ntohs(server_info.sin_port);
	    server_ip = inet_ntoa(server_info.sin_addr); //no error check, cause of checked
	    printf("UDP server started on %s:%d\n", server_ip, udp_port);

	    i = sizeof(server_address) / MAX_IP_LENGTH; //to stop select accessible ip-addresses
	}
    }
    if (bind_res < 0) {
	printf("bind (tcp) fault\n");
	perror(":::");
	goto error_in_parent;
    }

    cli_struct_len = sizeof(client_info);
    max_fd = max(tcp_listen_fd, udp_socket) + 1;
    while (1) {
	FD_ZERO(&mask_of_read_fd);
	FD_SET(tcp_listen_fd, &mask_of_read_fd);
	FD_SET(udp_socket, &mask_of_read_fd);
	select_res = select(max_fd, &mask_of_read_fd, NULL, NULL, NULL);
	if (select_res == -1) {
	    printf("select() fault\n");
	    perror(":::");
	    goto error_in_parent;
	}

	/* tcp */
	if (FD_ISSET(tcp_listen_fd, &mask_of_read_fd)) {
	    tcp_accept_fd = accept(tcp_listen_fd, (struct sockaddr *)&client_info,
					(socklen_t *)&cli_struct_len);
	    if (tcp_accept_fd < 0) {
		printf("accept(tcp) fault\n");
		perror(":::");
		goto error_in_parent;
	    }
	    pid = fork();
	    /* +1 to counter of pid, which not run exit(0) yet (for SIGINT correct handling) */
	    start_pid_cer++;
	    switch (pid) {
		case 0:
		    printf("child process created--%d--new session-------------------\n", getpid());
		    close(tcp_listen_fd);
		    close(udp_socket);

		    client_ip = inet_ntoa(client_info.sin_addr);
		    if ((bytes = recv(tcp_accept_fd, buf_for_recv, COND_MSG_SIZE, 0)) <= 0) {
			printf("recv() from %s fault\n", client_ip);
			perror(":::");
			goto error_in_child;
		    } else {
			printf("tspSERVER(%s:%d) recv (%d bytes) from client(%s:%d): %s\n",
			server_ip, tcp_port, bytes, client_ip, ntohs(client_info.sin_port), buf_for_recv);
		    }
		    if ((bytes = send(tcp_accept_fd, message, sizeof(message), 0)) <= 0) {
		        printf("send() to %s fault\n", client_ip);
			perror(":::");
			goto error_in_child;
		    } else {
		        printf("tcpSERVER(%s:%d) send (%d bytes) to client(%s:%d)\n",
		        server_ip, tcp_port, bytes, client_ip, ntohs(client_info.sin_port));
		    }
		    printf("\n");
		    close(tcp_accept_fd);
		    //+1 to counter of pid, which run exit(0)
		    //and -1 to counter of pid, which not run exit(0) yet
		    sem_wait(semka);
		    printf("[%d] in semka\n", getpid());
		    (*end_pid_cer)++;
		    start_pid_cer--;
		    sem_post(semka);

		    sem_unlink(semaph_name);
		    printf("[%d] ^.^ // %d\n", getpid(), *end_pid_cer);
		    munmap(end_pid_cer, mmap_size);
		    exit(0);
		case -1:
		    printf("fork() fault\n");
		    perror(":::");
		    goto error_in_parent;
		default:
		    printf("parent_move\n");
		    close(tcp_accept_fd);
		    break;
	    }
	}

	/* wait pids, only which run exit(0) */
	sem_wait(semka);
	printf("(%d) counters %d/%d\n", main_pid, *end_pid_cer, start_pid_cer);
	if (*end_pid_cer >= CLEAN_ZOMB_FREQ) {
	    printf("(%d) start cleaning\n", main_pid);
	    while (*end_pid_cer != 0) {
		wait(&status);
		(*end_pid_cer)--;
		start_pid_cer--;
	    }
	}
	sem_post(semka);

	/* udp */
	if (FD_ISSET(udp_socket, &mask_of_read_fd)) {
	    bytes = recvfrom(udp_socket, buf_for_recv,
				COND_MSG_SIZE, 0, (struct sockaddr *)&client_info,
				(socklen_t *)&cli_struct_len);
	    if (bytes <= 0) {
		printf("recvfrom() fault\n");
		perror(":::");
	    } else {
		printf("udpSERVER(%s:%d) recvfrom (%d bytes) client(%s:%d): %s\n",
			server_ip, ntohs(server_info.sin_port), bytes,
			inet_ntoa(client_info.sin_addr), ntohs(client_info.sin_port),
			buf_for_recv);
	    }
	    bytes = sendto(udp_socket, message, sizeof(message), 0,
				(struct sockaddr *)&client_info, cli_struct_len);
	    if (bytes <= 0) {
		printf("sendto() fault\n");
		perror(":::");
	    } else {
		printf("udpSERVER(%s:%d) sendto (%d bytes) client(%s:%d)\n",
			server_ip, ntohs(server_info.sin_port), bytes,
			inet_ntoa(client_info.sin_addr), ntohs(client_info.sin_port));
	    }
	}
    }

error_in_child:
    /* (??)    -------------------------    -------------     */
    /* semaphore and mmap are shared objects,                 */
    /* so if it close in child => it will be closed in parent */
    /* upd: shit, it's not true...                            */
    if (close(tcp_listen_fd) == -1) printf("[%d] close(listen) for nothing\n", getpid());
    if (close(tcp_accept_fd) == -1) printf("[%d] close(accept) for nothing\n", getpid());
    if (close(udp_socket)    == -1) printf("[%d] close(udp_sock) for nothing\n", getpid());
    if (munmap(end_pid_cer, mmap_size) == -1) printf("[%d] munmap() fault\n", getpid());
    if (sem_unlink(semaph_name) == -1) printf("[%d] sem_unlink() fault\n", getpid());
    exit(1);

error_in_parent:
    if (close(tcp_listen_fd) == -1) printf("(%d) close(listen) for nothing\n", main_pid);
    if (close(tcp_accept_fd) == -1) printf("(%d) close(accept) for nothing\n", main_pid);
    if (close(udp_socket)    == -1) printf("(%d) close(udp_sock) for nothing\n", main_pid);
    if (munmap(end_pid_cer, mmap_size) == -1) printf("(%d) munmap() fault\n", main_pid);
    if (sem_unlink(semaph_name) == -1) printf("(%d) sem_unlink() fault\n", main_pid);
    exit(1);
}

void sigint_hand (int signal) {
    if (main_pid == getpid()) {
	printf("\n(%d) SIGINT: need wait %d/%d\n", main_pid, *end_pid_cer, start_pid_cer);
	int status = 0;
	while (start_pid_cer != 0) {
	    wait(&status);
	    start_pid_cer--;
	    if (*end_pid_cer > 0) {
		(*end_pid_cer)--;
	    }
	}
	printf("(%d) SIGINT: end %d/%d\n", main_pid, *end_pid_cer, start_pid_cer);
	if (close(tcp_listen_fd) == -1) printf("(%d) close(listen) for nothing\n", main_pid);
	if (close(tcp_accept_fd) == -1) printf("(%d) close(accept) for nothing\n", main_pid);
	if (close(udp_socket)    == -1) printf("(%d) close(udp_sock) for nothing\n", main_pid);
	if (munmap(end_pid_cer, mmap_size) == -1) printf("(%d) munmap() fault\n", main_pid);
	if (sem_unlink(semaph_name) == -1) printf("(%d) sem_unlink() fault\n", main_pid);
	exit(0);
    }
}