#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <arpa/inet.h>

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

typedef struct fake_request {
	ring_buffer_t* ring;
	int debug;
} fake_request_t;

void* fake_request(void *arg) 
{
	fake_request_t* fr = (fake_request_t*)arg;
	ring_buffer_t* ring = fr->ring;
	int debug = fr->debug;

	struct pcap_pkthdr pkthdr;
	unsigned char packet[MAXBYTES2CAPTURE];
	int packet_len = 0;
	while (1) {
		ringbuffer_lock_read2(ring, &pkthdr, packet, &packet_len);

		struct ip *iphdr = (struct ip*)(packet + 14);
		struct tcphdr *tcphdr = (struct tcphdr*)(packet + 14 + 20);
		int size_ip = ntohs(iphdr->ip_len);
		int size_iphdr = sizeof(struct ip);
		int size_tcphdr = tcphdr->doff * 4;
		if (debug) {
			printf ("Received Size: %d\n", pkthdr.len);
			printf ("SRC IP: %s:\n", inet_ntoa(iphdr->ip_src));
			printf ("SRC PORT: %d:\n", ntohs(tcphdr->th_sport));
			printf ("DST IP: %s:\n", inet_ntoa(iphdr->ip_dst));
			printf ("DST PORT: %d:\n", ntohs(tcphdr->th_dport));
			printf ("PAYLOADLEN: %d:\n", size_ip - size_iphdr - size_tcphdr);
			printf ("SEQ: %u; ACK:%u\n", ntohl(tcphdr->seq), ntohl(tcphdr->ack_seq));
			print_app_data(packet, SIZE_ETHERHDR + size_iphdr + size_tcphdr, pkthdr.len);
		}
	}
	return arg;
}

int main(int argc, char* argv[]) 
{
	if (argc != 2) {
		printf("tcpdup <network-interface>");
		exit(1);
	}
	char filter_input[256] = "tcp and dst 10.23.53.150 and port 12345";
	int data_buffer_size = 100 * 1024 * 1024;
	int debug = 1;

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

	//start fake request thread
	fake_request_t fr;
	memset(&fr, 0, sizeof(fake_request_t));
	fr.ring = buffer;
	fr.debug = debug;
	pthread_t fake_request_thread;
	pthread_create(&fake_request_thread, NULL, &fake_request, &fr);

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

	pthread_join(fake_request_thread, NULL);
	destroy_ringbuffer(&buffer);
	return 0;
}
