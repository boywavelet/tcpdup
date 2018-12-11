#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "ringbuffer.h"

#define MAXBYTES2CAPTURE 2048
#define SIZE_ETHERHDR 14

void print_app_data(const unsigned char* packet, int start, int end) 
{
	int i = 0;
	printf("DATA:%d:", (end - start));
	for (i = start; i < end; ++i) {
		if (isprint(*(packet + i))) {
			printf("%c", *(packet + i));
		} else if (*(packet + i) == 0) {
			printf("$");
		} else {
			printf("#");
		}
	}
	printf("\n");
}

typedef struct mock_request {
	ring_buffer_t* ring;
	int debug;
	char *data_server_ip;
	u_int16_t data_server_port;
} mock_request_t;

int init_client_socket(char* ip, u_int16_t port) 
{
	int sock = socket(AF_INET, SOCK_STREAM, 0); 
	struct sockaddr_in server_addr;
	bzero(&server_addr, sizeof(server_addr));

	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port);

	inet_pton(AF_INET, ip, &server_addr.sin_addr);

	int ret = connect(sock, (const struct sockaddr *)&server_addr, sizeof(server_addr));
	if (ret != 0) {
		perror("connect failed");
		return -1;
	} 
	return sock;
}

void free_client_socket(int sock)
{
	close(sock);
}

int write_client_data(
		int sock, 
		struct pcap_pkthdr *pkthdr, 
		unsigned char* packet, int packet_len) 
{
	struct iovec iov[2];
	iov[0].iov_base = pkthdr;
	iov[0].iov_len = sizeof(struct pcap_pkthdr);
	iov[1].iov_base = packet;
	iov[1].iov_len = packet_len;
	if (writev(sock, iov, 2) < 0) {
		perror("write data failed \n");
		return -1;
	}
	return 0;
}

void* retransfer(void *arg) 
{
	mock_request_t* fr = (mock_request_t*)arg;
	ring_buffer_t* ring = fr->ring;
	int debug = fr->debug;

	char* ip = fr->data_server_ip;
	u_int16_t data_server_port = fr->data_server_port;
	int sock = init_client_socket(ip, data_server_port);
	if (sock < 0) {
		printf("init client_socket failed \n");
		exit(1);
	}

	struct pcap_pkthdr pkthdr;
	unsigned char packet[MAXBYTES2CAPTURE];
	int packet_len = 0;
	while (1) {
		ringbuffer_lock_read2(ring, &pkthdr, packet, &packet_len);

		struct ip *iphdr = (struct ip*)(packet + SIZE_ETHERHDR);
		struct tcphdr 
			*tcphdr = (struct tcphdr*)(packet + SIZE_ETHERHDR + sizeof(struct ip));
		int size_ip = ntohs(iphdr->ip_len);
		int size_iphdr = sizeof(struct ip);
		int size_tcphdr = tcphdr->doff * 4;
		int payload_len = size_ip - size_iphdr - size_tcphdr;
		if (debug) {
			printf ("Received Size: %d\n", pkthdr.len);
			printf ("SRC IP: %s:\n", inet_ntoa(iphdr->ip_src));
			printf ("SRC PORT: %d:\n", ntohs(tcphdr->th_sport));
			printf ("DST IP: %s:\n", inet_ntoa(iphdr->ip_dst));
			printf ("DST PORT: %d:\n", ntohs(tcphdr->th_dport));
			printf ("PAYLOADLEN: %d:\n", payload_len);
			printf ("SEQ: %u; ACK:%u\n", ntohl(tcphdr->seq), ntohl(tcphdr->ack_seq));
			printf ("FLAG syn: %d, fin:%d, rst:%d, ack:%d\n", 
					tcphdr->syn, tcphdr->fin, tcphdr->rst, tcphdr->ack);
			print_app_data(packet, SIZE_ETHERHDR + size_iphdr + size_tcphdr, pkthdr.len);
		}
		
		if (0 != write_client_data(sock, &pkthdr, packet, packet_len)) {
			//TODO need to process server-socket close, in case close_wait
			printf("write data failed \n");
			free_client_socket(sock);
			sock = init_client_socket(ip, data_server_port);
			if (sock < 0) {
				printf("init client_socket failed \n");
				exit(1);
			}
		}
	}

	free_client_socket(sock);
	return arg;
}

int main(int argc, char* argv[]) 
{
	if (argc != 2) {
		printf("tcpdup <network-interface>\n");
		exit(1);
	}
	//TODO init all fields
	char filter_input[256] = "tcp and ((dst 10.23.53.150 and dst port 12345) or (src 10.23.53.150 and src port 12345))";
	int data_buffer_size = 100 * 1024 * 1024;
	int debug = 1;
	char* data_server_ip = "10.23.53.150";
	u_int16_t data_server_port = 23456;

	int count = 0;
	bpf_u_int32 netaddr = 0, mask = 0;
	pcap_t* descr = NULL;
	struct bpf_program filter;
	struct pcap_pkthdr pkthdr;
	const unsigned char *packet = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
	memset(errbuf, 0, PCAP_ERRBUF_SIZE);
	
	descr = pcap_open_live(argv[1], MAXBYTES2CAPTURE, 1, 512, errbuf);
	pcap_lookupnet(argv[1], &netaddr, &mask, errbuf);
	pcap_compile(descr, &filter, filter_input, 1, mask);
	pcap_setfilter(descr, &filter);

	int linktype = pcap_datalink(descr);
	if (linktype != 1) {
		printf ("Link Type: %d\n, Not ethernet", linktype);
		exit(1);
	}

	//we can have multiple buffer, and cap packet mod by host:port
	ring_buffer_t* buffer = NULL;
	init_ringbuffer(&buffer, data_buffer_size);

	//start mock request thread
	mock_request_t fr;
	memset(&fr, 0, sizeof(mock_request_t));
	fr.ring = buffer;
	fr.debug = debug;
	fr.data_server_ip = data_server_ip;
	fr.data_server_port = data_server_port;
	
	pthread_t retransfer_thread;
	pthread_create(&retransfer_thread, NULL, &retransfer, &fr);
	while(1) {
		packet = NULL;
		packet = pcap_next(descr, &pkthdr);
		if (packet == NULL) {
			continue;
		}

		//MAYBE check write fail
		ringbuffer_lock_write2(buffer, 
				&pkthdr, sizeof(struct pcap_pkthdr), 
				packet, pkthdr.len);

		++count;
		printf ("CURRENT READ: %d, WRITE:%d, AVAIL:%d\n", 
				buffer->read_pos, buffer->write_pos, get_ringbuffer_avail_size(buffer));
	}

	pthread_join(retransfer_thread, NULL);
	destroy_ringbuffer(&buffer);
	return 0;
}
