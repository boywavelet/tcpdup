#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "ringbuffer.h"

#define MAXBYTES2CAPTURE 2048

void* fake_request(void *arg) 
{
	ring_buffer_t* ring = (ring_buffer_t*)arg;
	struct pcap_pkthdr pkthdr;
	unsigned char packet[MAXBYTES2CAPTURE];
	int packet_len = 0;
	while (1) {
		ringbuffer_lock_read2(ring, &pkthdr, packet, &packet_len);

		struct ip *iphdr = (struct ip*)(packet + 14);
		struct tcphdr *tcphdr = (struct tcphdr*)(packet + 14 + 20);
		printf ("FAKE Received Size: %d\n", pkthdr.len);
		printf ("FAKE SRC IP: %s:\n", inet_ntoa(iphdr->ip_src));
		printf ("FAKE SRC PORT: %d:\n", ntohs(tcphdr->th_sport));
		printf ("FAKE DST IP: %s:\n", inet_ntoa(iphdr->ip_dst));
		printf ("FAKE DST PORT: %d:\n", ntohs(tcphdr->th_dport));
	}
	return arg;
}

int main(int argc, char* argv[]) 
{
	if (argc != 2) {
		printf("tcpdup <network-interface>");
		exit(1);
	}
	char filter_input[256] = "tcp and dst 10.23.53.150 and port 9097";
	int data_buffer_size = 100 * 1024 * 1024;

	int count = 0;
	bpf_u_int32 netaddr = 0, mask = 0;

	pcap_t* descr = NULL;
	struct bpf_program filter;
	struct ip *iphdr = NULL;
	struct tcphdr *tcphdr = NULL;

	struct pcap_pkthdr pkthdr;
	const unsigned char *packet = NULL;

	char errbuf[PCAP_ERRBUF_SIZE];
	memset(errbuf, 0, PCAP_ERRBUF_SIZE);
	
	descr = pcap_open_live(argv[1], MAXBYTES2CAPTURE, 1, 512, errbuf);
	pcap_lookupnet(argv[1], &netaddr, &mask, errbuf);
	pcap_compile(descr, &filter, filter_input, 1, mask);
	pcap_setfilter(descr, &filter);

	int linktype = pcap_datalink(descr);
	printf ("Link Type: %d\n", linktype);
	printf ("Size of ip : %ld\n", sizeof(struct ip));

	//we can have multiple buffer, and cap packet mod by host:port
	ring_buffer_t* buffer = NULL;
	init_ringbuffer(&buffer, data_buffer_size);

	//start fake request thread
	pthread_t fake_request_thread;
	pthread_create(&fake_request_thread, NULL, &fake_request, buffer);

	while(1) {
		printf("/////////////////////////////////////////\n");
		packet = pcap_next(descr, &pkthdr);

		//TODO check write fail
		ringbuffer_lock_write2(buffer, 
				&pkthdr, sizeof(struct pcap_pkthdr), 
				packet, pkthdr.len);

		++count;
		iphdr = (struct ip*)(packet + 14);
		tcphdr = (struct tcphdr*)(packet + 14 + 20);
		printf ("Received counter: %d\n", count);
		printf ("Received Size: %d\n", pkthdr.len);
		printf ("SRC IP: %s:\n", inet_ntoa(iphdr->ip_src));
		printf ("SRC PORT: %d:\n", ntohs(tcphdr->th_sport));
		printf ("DST IP: %s:\n", inet_ntoa(iphdr->ip_dst));
		printf ("DST PORT: %d:\n", ntohs(tcphdr->th_dport));

		printf ("CURRENT READ: %d, WRITE:%d, AVAIL:%d\n", 
				buffer->read_pos, buffer->write_pos, get_ringbuffer_avail_size(buffer));
	}

	pthread_join(fake_request_thread, NULL);
	destroy_ringbuffer(&buffer);
	return 0;
}
