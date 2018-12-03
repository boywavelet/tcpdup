#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap.h>

#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

#define MAXBYTES2CAPTURE 2048

int main(int argc, char* argv[]) {

	if (argc != 2) {
		printf("tcpdup <network-interface>");
		exit(1);
	}
	char filter_input[256] = "tcp and dst 10.23.53.150 and port 9097";

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
	printf ("Size of ip : %d\n", sizeof(struct ip));

	while(count < 100) {
		printf("/////////////////////////////////////////\n");
		packet = pcap_next(descr, &pkthdr);

		iphdr = (struct ip*)(packet + 14);

		tcphdr = (struct tcphdr*)(packet + 14 + 20);

		printf ("Received counter: %d\n", ++count);
		printf ("Received Size: %d\n", pkthdr.len);
//		int i = 0;
//		for (i = 42; i < pkthdr.len; ++i) {
//			if (isprint(packet[i])) {
//				printf("%c", packet[i]);
//			} else {
//				printf (".");
//			}
//		}
		
		printf ("SRC IP: %s:\n", inet_ntoa(iphdr->ip_src));
		printf ("DST IP: %s:\n", inet_ntoa(iphdr->ip_dst));



		printf ("SRC PORT: %d:\n", ntohs(tcphdr->th_sport));
		printf ("DST PORT: %d:\n", ntohs(tcphdr->th_dport));
	}


	return 0;
}
