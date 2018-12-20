#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/ip.h>
#include <sys/epoll.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "tcpdup_net_util.h"
#include "tcpdup_util.h"
#include "tcpdup_ringbuffer.h"
#include "tcpdup_container.h"

void str_echo(int sockfd)
{
	int len = 0;
	char buf[2048];
	while ((len = read(sockfd, buf, 2000)) > 0) {
		int i;
again:
		printf("Read:%d\n", len);
		for (i = 0; i < len; ++i) {
			if (isprint(buf[i])) {
				printf("%c", buf[i]);
			}
		}
		printf("\n");
		//write(sockfd, buf, len);
	}

	if (len < 0 && errno == EINTR) {
		goto again;
	} else if (len < 0) {
		printf("read error\n");
		close(sockfd);
		exit(200);
	} else if (len == 0) {
		printf("read exit\n");
		close(sockfd);
		exit(0);
	}
}

typedef struct transfer_config {
	struct in_addr ori_dst;
	u_int16_t ori_dst_port;
	struct sockaddr_in transfer_addr;
	//TODO config fields
} transfer_config_t;

void clean_fd(
		fd_info_t *fd_info,
		int epfd,
		fix_hashmap_t *fd_map,
		fix_hashmap_t *ipport_map)
{
	int fd = fd_info->fd;
	char *ipport = fd_info->ipport;
	delnode_fix_hashmap(fd_map, &fd);
	delnode_fix_hashmap(ipport_map, ipport);
	destroy_fd_info(&fd_info);
	fd_info = NULL;
	epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL);
	close(fd);
}

void process_packet(
		transfer_config_t *conf, 
		int epfd,
		struct pcap_pkthdr *pkthdr, 
		char* packet, 
		fix_hashmap_t *fd_map,
		fix_hashmap_t *ipport_map)
{
	char ipport[6];
	struct epoll_event event;
	struct ip *iphdr = (struct ip*)(packet + SIZE_ETHERHDR);
	struct tcphdr 
		*tcphdr = (struct tcphdr*)(packet + SIZE_ETHERHDR + sizeof(struct ip));
	int size_ip = ntohs(iphdr->ip_len);
	int size_iphdr = sizeof(struct ip);
	int size_tcphdr = tcphdr->doff * 4;
	int payload_len = size_ip - size_iphdr - size_tcphdr;
	if (memcmp(&iphdr->ip_dst, &conf->ori_dst, sizeof(struct in_addr)) == 0 
			&& ntohs(tcphdr->dest) == conf->ori_dst_port) {
		//process server-receive data
		memcpy(ipport, &iphdr->ip_src, 4);
		memcpy(ipport + 4, &tcphdr->source, 2);
		fd_info_t *fd_info = lookup_fix_hashmap(ipport_map, ipport);
		if (fd_info == NULL && tcphdr->syn) {
			//create fd_info, record the start seq, create fd, put it to epoll
			int fd = socket(AF_INET, SOCK_STREAM, 0); 
			int ret = connect(fd, 
					(const struct sockaddr *)&conf->transfer_addr, 
					sizeof(struct sockaddr_in));
			int connected = 1;
			if (ret != 0) {
				connected = 0;
				if (errno == EINPROGRESS) {
					event.events = EPOLLOUT;
					event.data.fd = fd;
					epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &event);
					init_fd_info(&fd_info, fd, ipport, connected, tcphdr->seq);
					insert_fix_hashmap(fd_map, &fd_info->fd, fd_info); 
					insert_fix_hashmap(ipport_map, &fd_info->ipport, fd_info); 
				} else {
					close(fd);
				}
			} else {
				//nonblock connect complete immediately, rare
				event.events = EPOLLOUT | EPOLLIN;
				event.data.fd = fd;
				epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &event);
				init_fd_info(&fd_info, fd, ipport, connected, tcphdr->seq);
				insert_fix_hashmap(fd_map, &fd, fd_info); 
				insert_fix_hashmap(ipport_map, ipport, fd_info); 
			}
		} else if (fd_info && (tcphdr->fin || tcphdr->rst)) { 
			//free fd_info, epoll remove
			clean_fd(fd_info, epfd, fd_map, ipport_map);
		} else if (fd_info && payload_len > 0) {
			//emplace request data, try to write
			char *payload = packet + SIZE_ETHERHDR + size_iphdr + size_tcphdr;
			fd_info_emplace_data(fd_info, payload, payload_len, tcphdr->seq, 0);
			fd_info_write_data(fd_info);
			if (fd_info->closed) {
				clean_fd(fd_info, epfd, fd_map, ipport_map);
			}
		} else {
			//1. data_len = 0, probably pure ack, nothing to do 
			//2. fd_info == NULL && !tcphdr->syn, bypass mid-data
			//3. fd_info != NULL && tcphdr->syn, weird, ignore
			//DO NOTHING 
		}
	} else {
		//server-response data, process fin && rst
		memcpy(ipport, &iphdr->ip_dst, 4);
		memcpy(ipport + 4, &tcphdr->dest, 2);
		fd_info_t *fd_info = lookup_fix_hashmap(ipport_map, ipport);
		if (fd_info != NULL && (tcphdr->fin || tcphdr->rst)) {
			//MAYBE try to write-out the remaining data first
			clean_fd(fd_info, epfd, fd_map, ipport_map);
		}
	}
}

void process_new_data(
		transfer_config_t *conf, 
		int epfd,
		ring_buffer_t *buffer, 
		fix_hashmap_t *fd_map,
		fix_hashmap_t *ipport_map)
{
	struct pcap_pkthdr pkthdr;
	char buf[2048];
	while (1) {
		int pkthdr_size = sizeof(struct pcap_pkthdr);
		if (get_ringbuffer_avail_read_size(buffer) > pkthdr_size) {
			ringbuffer_read(buffer, &pkthdr, pkthdr_size);
			int pack_len = pkthdr.len;
			if (get_ringbuffer_avail_read_size(buffer) > pack_len) {
				ringbuffer_read(buffer, buf, pack_len);
				//process head + data
				process_packet(conf, epfd, &pkthdr, buf, fd_map, ipport_map);
			} else {
				ringbuffer_unread(buffer, pkthdr_size);
				break;
			}
		} else {
			break;
		}
	}
}

int fd_hash(void *key) 
{
	int* pfd = (int *)key;
	return *pfd;
}

int fd_equal(void *keyvalue, void *key)
{
	fd_info_t* pkv = (fd_info_t *)keyvalue;
	int *pfd = (int *)key;
	return pkv->fd == *pfd;
}

int ipport_hash(void *key) 
{
	//ipport is char[6], 0~5, make range 2~5 as int
	const char* pfd = (const char*)key;
	return *(int *)(pfd + 2);
}

int ipport_equal(void *keyvalue, void *key)
{
	//ipport is char[6]
	const char* pfd = (const char*)key;
	fd_info_t* pkv = (fd_info_t *)keyvalue;
	return memcmp(pfd, pkv->ipport, 6) == 0; 
}

void epoll_transfer(transfer_config_t *conf, int sockfd) 
{
	int max_con_size = 128;
	int epfd = epoll_create(max_con_size);
	if (epfd < 0) {
		perror("epoll create failed");
	}
	ring_buffer_t* buffer = NULL;
	init_ringbuffer(&buffer, getpagesize());

	fix_hashmap_t *fd_map = NULL;
	init_fix_hashmap(&fd_map, max_con_size, fd_hash, fd_equal); 
	//both ip && port are network byte order
	fix_hashmap_t *ipport_map = NULL;
	init_fix_hashmap(&ipport_map, max_con_size, ipport_hash, ipport_equal); 

	//set sockfd non-block, put it to epoll-loop
	set_fd_nonblock(sockfd);
	struct epoll_event event;
	event.events = EPOLLIN;
	event.data.fd = sockfd;
	epoll_ctl(epfd, EPOLL_CTL_ADD, sockfd, &event);
	
	//read from sockfd and write data to buffer
	char buf[2048];
	while (epoll_wait(epfd, &event, 1, -1)) {
		int fd = event.data.fd;
		if (fd == sockfd) {
			if (event.events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) {
				close(fd);
				epoll_ctl(epfd, EPOLL_CTL_DEL, fd, &event);
				break;
			} else if (event.events & EPOLLIN) {
				//maybe read until drain
				int len = read(fd, buf, 2000);
				printf("Read len:%d\n", len);
				if (len <= 0) {
					close(fd);
					epoll_ctl(epfd, EPOLL_CTL_DEL, fd, &event);
					break;
				} else {
					ringbuffer_write(buffer, buf, len);
					process_new_data(conf, epfd, buffer, fd_map, ipport_map);
				}
			}
		} else {
			fd_info_t *fd_info = lookup_fix_hashmap(fd_map, &fd);
			if (fd_info == NULL) {
				//won't happen though
				epoll_ctl(epfd, EPOLL_CTL_DEL, fd, &event);
				continue;
			}
			if (event.events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) {
				clean_fd(fd_info, epfd, fd_map, ipport_map);
			} else { 
				if (event.events & EPOLLOUT) {
					//1. check if connected: add EPOLLIN  2. write remain data
					if (!fd_info->connected) {
						//nonblock connect success
						fd_info->connected = 1;
						event.events = EPOLLOUT | EPOLLIN;
						event.data.fd = fd;
						epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &event);
					}
					fd_info_write_data(fd_info);
					if (fd_info->closed) {
						clean_fd(fd_info, epfd, fd_map, ipport_map);
					}
				}
				if (event.events & EPOLLIN) {
					//read & discard
					//maybe read until drain
					read(fd, buf, 2000);
				}
			}
		}
	}

	//MAYBE need to process remain fd's operations
	//e.g. write all pending data
	
	destroy_fix_hashmap(&ipport_map);
	destroy_fix_hashmap(&fd_map);
	destroy_ringbuffer(&buffer);
	close(epfd);

	//in case of the outer loop in main
	exit(0);
}

int main() 
{
	signal(SIGPIPE, SIG_IGN);
	//TODO init conf
	transfer_config_t conf;
	int listenfd, connfd;
	pid_t childpid;

	socklen_t clilen;
	struct sockaddr_in cliaddr, servaddr;

	listenfd = socket(AF_INET, SOCK_STREAM, 0);
	int enable = 1;
	setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(23456);

	bind(listenfd, (const struct sockaddr *)&servaddr, sizeof(servaddr));
	listen(listenfd, 512);

	while (1) {
		clilen = sizeof(cliaddr);
		connfd = accept(listenfd, (struct sockaddr *)&cliaddr, &clilen);

		if ((childpid = fork()) == 0) {
			close(listenfd);
			epoll_transfer(&conf, connfd);
		} else {
			close(connfd);
		}
	}

	return 0;
}

