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
#include <arpa/inet.h>
#include "tcpdup_net_util.h"
#include "tcpdup_util.h"
#include "tcpdup_ringbuffer.h"
#include "tcpdup_container.h"

typedef struct transfer_config {
	struct in_addr ori_dst;
	u_int16_t ori_dst_port;
	struct sockaddr_in transfer_addr;
	int ewait_time;
	int debug;
} transfer_config_t;

//TODO two working modes
//1. After Sending All Request-Data, Close
//2. Close in-active(e.g. 1000ms no read) Sockets in each epoll-iteration,

void force_clean_fd(
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
	//MAYBE it's better setlinger to send RST instead of FIN
	close(fd);
}

void clean_fd(
		fd_info_t *fd_info,
		int epfd,
		fix_hashmap_t *fd_map,
		fix_hashmap_t *ipport_map)
{
	force_clean_fd(fd_info, epfd, fd_map, ipport_map);
}

void process_packet(
		transfer_config_t *conf, 
		int epfd,
		struct pcap_pkthdr *pkthdr, 
		char* packet, 
		linked_list_t *time_list_head,
		fix_hashmap_t *fd_map,
		fix_hashmap_t *ipport_map)
{
	int debug = conf->debug;
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
			&& tcphdr->dest == conf->ori_dst_port) {
		//process server-receive data
		memcpy(ipport, &iphdr->ip_src, 4);
		memcpy(ipport + 4, &tcphdr->source, 2);
		fd_info_t *fd_info = lookup_fix_hashmap(ipport_map, ipport);
		if (fd_info == NULL && tcphdr->syn) {
			//create fd_info, record the start seq, create fd, put it to epoll
			int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0); 
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
					init_fd_info(&fd_info, fd, ipport, connected, ntohl(tcphdr->seq));
					linked_list_add_tail(time_list_head, &fd_info->time_list);
					insert_fix_hashmap(fd_map, &fd_info->fd, fd_info); 
					insert_fix_hashmap(ipport_map, &fd_info->ipport, fd_info); 
				} else {
					close(fd);
				}
			} else {
				//nonblock connect complete immediately, rare
				//no data to write at first
				event.events = EPOLLIN;
				event.data.fd = fd;
				epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &event);
				init_fd_info(&fd_info, fd, ipport, connected, ntohl(tcphdr->seq));
				linked_list_add_tail(time_list_head, &fd_info->time_list);
				insert_fix_hashmap(fd_map, &fd, fd_info); 
				insert_fix_hashmap(ipport_map, ipport, fd_info); 
			}
			if (debug > 0) {
				printf("Syn. Open new Connection\n");
			}
		} else if (fd_info && (tcphdr->fin || tcphdr->rst)) { 
			//packet may contain both fin|rst and data
			if (payload_len > 0) {
				char *payload = packet + SIZE_ETHERHDR + size_iphdr + size_tcphdr;
				fd_info_emplace_data(fd_info, payload, payload_len, ntohl(tcphdr->seq), 0);
			}

			//second-last chance to write data
			fd_info_write_data(fd_info);
			//check whether we have full-data 
			if (!fd_info_is_consecutive(fd_info)) {
				if (debug >= 0 
						&& (fd_info->stat_num_packet > 0
						|| fd_info->stat_total_write == 0)) {
					printf("Fin|Rst. Close Connection, %d, %d\n", 
							fd_info->stat_num_packet, fd_info->stat_total_write);
				}
				//free fd_info, epoll remove
				clean_fd(fd_info, epfd, fd_map, ipport_map);
			} else {
				fd_info_append_fin(fd_info);
				//close operation is postponed to write
				if (debug > 0) {
					printf("Fin|Rst. Defer Close, %d\n", fd_info->stat_num_packet);
				}
			}
		} else if (fd_info && payload_len > 0) {
			//emplace request data, try to write
			char *payload = packet + SIZE_ETHERHDR + size_iphdr + size_tcphdr;
			fd_info_emplace_data(fd_info, payload, payload_len, ntohl(tcphdr->seq), 0);
			fd_info_write_data(fd_info);
			//only if remain data, modify epoll events
			if (is_fd_info_has_writable_data(fd_info)) {
				event.events = EPOLLIN | EPOLLOUT;
				event.data.fd = fd_info->fd;
				epoll_ctl(epfd, EPOLL_CTL_MOD, fd_info->fd, &event);
			}
			if (fd_info->closed) {
				clean_fd(fd_info, epfd, fd_map, ipport_map);
			}
			if (debug > 0) {
				printf("Client Data. transfer\n");
			}
		} else {
			//1. data_len = 0, probably pure ack, nothing to do 
			//2. fd_info == NULL && !tcphdr->syn, bypass mid-data
			//3. fd_info != NULL && tcphdr->syn, weird, ignore
			//DO NOTHING 
			if (debug > 0) {
				printf("ack|old-con-data. bypass\n");
			}
		}
	} else {
		//server-response data, process fin && rst
		memcpy(ipport, &iphdr->ip_dst, 4);
		memcpy(ipport + 4, &tcphdr->dest, 2);
		fd_info_t *fd_info = lookup_fix_hashmap(ipport_map, ipport);
		if (fd_info != NULL && (tcphdr->fin || tcphdr->rst)) {
			//try to write-out the remaining data first
			fd_info_write_data(fd_info);
			if (!fd_info_is_consecutive(fd_info)) {
				clean_fd(fd_info, epfd, fd_map, ipport_map);
				if (debug >= 0) {
					printf("Server Fin|Rst, close connection\n");
				}
			} else {
				fd_info_append_fin(fd_info);
				if (debug > 0) {
					printf("Server Fin|Rst, defer close\n");
				}
			}
		} else {
			if (debug > 0) {
				printf("Server Resp, bypass\n");
			}
		}
	}
}

void process_new_data(
		transfer_config_t *conf, 
		int epfd,
		ring_buffer_t *buffer, 
		linked_list_t *time_list_head,
		fix_hashmap_t *fd_map,
		fix_hashmap_t *ipport_map)
{
	//MAYBE: one big read may contain many packets of one connection
	//e.g. SYN, DATA, FIN. connection may be not ready when check the data,
	//possibly lose request
	struct pcap_pkthdr pkthdr;
	char *buf = malloc(2048);
	while (1) {
		int pkthdr_size = sizeof(struct pcap_pkthdr);
		if (get_ringbuffer_avail_read_size(buffer) > pkthdr_size) {
			ringbuffer_read(buffer, &pkthdr, pkthdr_size);
			int pack_len = pkthdr.len;
			if (get_ringbuffer_avail_read_size(buffer) >= pack_len) {
				ringbuffer_read(buffer, buf, pack_len);
				//process head + data
				process_packet(conf, epfd, &pkthdr, buf, time_list_head, 
						fd_map, ipport_map);
			} else {
				ringbuffer_unread(buffer, pkthdr_size);
				break;
			}
		} else {
			break;
		}
	}
	free(buf);
}

int fd_hash(void *key) 
{
	int *pfd = (int *)key;
	return *pfd;
}

int fd_equal(void *keyvalue, void *key)
{
	fd_info_t *pkv = (fd_info_t *)keyvalue;
	int *pfd = (int *)key;
	return pkv->fd == *pfd;
}

int ipport_hash(void *key) 
{
	//ipport is char[6], 0~5, make range 2~5 as int
	const char *pfd = (const char *)key;
	return *(int *)(pfd + 2);
}

int ipport_equal(void *keyvalue, void *key)
{
	//ipport is char[6]
	const char *pfd = (const char *)key;
	fd_info_t *pkv = (fd_info_t *)keyvalue;
	return memcmp(pfd, pkv->ipport, 6) == 0; 
}

void process_time_events(
		int epfd,
		int expire_time,
		long current_milli,
		linked_list_t *time_list_head,
		fix_hashmap_t *fd_map,
		fix_hashmap_t *ipport_map)
{
	linked_list_t *pos, *iter_pos;
	fd_info_t *entry;
	linked_list_for_each_safe(pos, iter_pos, time_list_head) {
		entry = linked_list_entry(pos, fd_info_t, time_list);
		if (current_milli - entry->last_active_time > expire_time) {
			force_clean_fd(entry, epfd, fd_map, ipport_map);
		} else {
			break;
		}
	}
}

void epoll_transfer(transfer_config_t *conf, int sockfd) 
{
	int debug = conf->debug;
	int max_con_size = 1024;
	int epfd = epoll_create(max_con_size);
	if (epfd < 0) {
		perror("epoll create failed");
	}
	ring_buffer_t* buffer = NULL;
	init_ringbuffer(&buffer, getpagesize());

	linked_list_t time_list_head;
	init_linked_list(&time_list_head);
	fix_hashmap_t *fd_map = NULL;
	init_fix_hashmap(&fd_map, max_con_size, fd_hash, fd_equal); 
	//both ip && port are network byte order
	fix_hashmap_t *ipport_map = NULL;
	init_fix_hashmap(&ipport_map, max_con_size, ipport_hash, ipport_equal); 

	//set sockfd non-block, put it to epoll-loop
	set_fd_nonblock(sockfd);

	//MAYBE destroy LONG-TIME IDLE socket
	struct epoll_event *events = malloc(sizeof(struct epoll_event) * max_con_size);
	int num_events = 0;

	events[0].events = EPOLLIN;
	events[0].data.fd = sockfd;
	epoll_ctl(epfd, EPOLL_CTL_ADD, sockfd, &events[0]);
	
	//read from sockfd and write data to buffer
	char *buf = malloc(2048);
	int ewait_time = conf->ewait_time; 
	int expire_time = ewait_time;
	long current_milli = 0;
	while (1) {
		num_events = epoll_wait(epfd, events, max_con_size, ewait_time);
		current_milli = get_current_milliseconds();
		int i = 0;
		for (; i < num_events; ++i) {
			int fd = events[i].data.fd;
			if (fd == sockfd) {
				if (events[i].events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) {
					close(fd);
					epoll_ctl(epfd, EPOLL_CTL_DEL, fd, &events[i]);
					goto transfer_end;
				} else if (events[i].events & EPOLLIN) {
					//maybe read until drain
					int len = read(fd, buf, 2000);
					if (len == 0) {
						close(fd);
						epoll_ctl(epfd, EPOLL_CTL_DEL, fd, &events[i]);
						goto transfer_end;
					}
					if (debug >= 2) {
						printf("Read data len:%d\n", len);
					}
					ringbuffer_write(buffer, buf, len);
					process_new_data(conf, epfd, buffer, 
							&time_list_head, fd_map, ipport_map);
				}
			} else {
				fd_info_t *fd_info = lookup_fix_hashmap(fd_map, &fd);
				if (fd_info == NULL) {
					//won't happen though
					epoll_ctl(epfd, EPOLL_CTL_DEL, fd, &events[i]);
					continue;
				}
				if (events[i].events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) {
					clean_fd(fd_info, epfd, fd_map, ipport_map);
				} else { 
					if (events[i].events & EPOLLIN) {
						//read & discard, read until drain
						int len = 0;
						while ((len = read(fd, buf, 2000)) == 2000);
						//if read 0, close
						if (len == 0) {
							clean_fd(fd_info, epfd, fd_map, ipport_map);
						}
						//update last active time
						fd_info_touch(fd_info, current_milli, &time_list_head);
					}
					if (events[i].events & EPOLLOUT) {
						//1. check if connected: add EPOLLIN  2. write remain data
						if (!fd_info->connected) {
							if (debug >= 1) {
								printf("Connection success%d\n", fd_info->stat_num_packet);
							}
							//nonblock connect success
							fd_info->connected = 1;
							events[i].events = EPOLLIN;
						}
						fd_info_write_data(fd_info);
						if (is_fd_info_has_writable_data(fd_info)) {
							events[i].events = EPOLLIN | EPOLLOUT;
						}
						if (fd_info->closed) {
							if (debug >= 1) {
								printf("EP:close mock con%d\n", fd_info->stat_num_packet);
							}
							clean_fd(fd_info, epfd, fd_map, ipport_map);
						} else {
							//MAYBE set only when there is remain data
							//EPOLLIN is always ON for connected socket
							epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &events[i]);
						}
					}
				}
			}
		}

		//TODO check work mode
		process_time_events(epfd, expire_time, current_milli, &time_list_head, fd_map, ipport_map);
	}

	//MAYBE need to process remain fd's operations
	//e.g. write all pending data
	
transfer_end:
	free(buf);
	free(events);
	destroy_fix_hashmap(&ipport_map, 0);
	destroy_fix_hashmap(&fd_map, 1);
	destroy_ringbuffer(&buffer);
	close(epfd);

	exit(0);
}

void print_help() 
{
	printf("transfer -t <ip> -q <port> -s <ip> -p <port>\n");
	printf("    -t <ip>    monitored server ip\n");
	printf("    -q <port>  monitored server port\n");
	printf("    -s <ip>    transfer server ip\n");
	printf("    -p <port>  transfer server port\n");
	printf("    -e <time>  [OPTIONAL:1000] epoll wait time\n");
	printf("    -d <flag>  [OPTIONAL:0] debug\n");
	printf("    -h         Show This\n");
}

void init_config(transfer_config_t *pcon, int argc, char **argv)
{
	bzero(pcon, sizeof(transfer_config_t));
	char* data_server_ip = "127.0.0.1";
	u_int16_t data_server_port = 0;
	char* monitor_server_ip = "127.0.0.1";
	u_int16_t monitor_server_port = 0;
	int ewait_time = 1000; //ms
	int debug = 0;
	char ch = '\0';
	while ((ch = getopt(argc, argv, "s:p:t:q:e:d:h"))!= -1) {
		switch(ch) {
			case 's': 
				data_server_ip = optarg;
				break;
			case 'p': 
				data_server_port = (u_int16_t)(atoi(optarg));
				break;
			case 't': 
				monitor_server_ip = optarg;
				break;
			case 'q': 
				monitor_server_port = (u_int16_t)(atoi(optarg));
				break;
			case '3': 
				ewait_time = atoi(optarg);
				break;
			case 'd': 
				debug = atoi(optarg);
				break;
			case 'h': 
				print_help();
				exit(0);
		}   
	}

	inet_pton(AF_INET, monitor_server_ip, &pcon->ori_dst);
	pcon->ori_dst_port = htons(monitor_server_port);
	pcon->transfer_addr.sin_family = AF_INET;
	pcon->transfer_addr.sin_port = htons(data_server_port);
	inet_pton(AF_INET, data_server_ip, &pcon->transfer_addr.sin_addr);
	pcon->ewait_time = ewait_time;
	pcon->debug = debug;
}

int main(int argc, char **argv) 
{
	signal(SIGPIPE, SIG_IGN);
	signal(SIGCHLD, SIG_IGN);
	if (argc < 2) {
		print_help();
		exit(0);
	}

	transfer_config_t conf;
	init_config(&conf, argc, argv);
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

