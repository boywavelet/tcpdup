#include "tcpdup_net_util.h"
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>

void set_fd_nonblock(int fd) 
{
	int flags = fcntl(fd, F_GETFL, 0); 
	fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int fd_packet_cmp(void *payload1, void *payload2)
{
	fd_packet_t *fpack1 = (fd_packet_t *)payload1;
	fd_packet_t *fpack2 = (fd_packet_t *)payload2;
	return (int)(fpack1->tcp_seq - fpack2->tcp_seq);
}

void init_fd_info(fd_info_t **ppfi, int fd, char *ipport, unsigned int tcp_seq)
{
	*ppfi = malloc(sizeof(fd_info_t));
	(*ppfi)->fd = fd;
	memcpy((*ppfi)->ipport, ipport, 6);
	(*ppfi)->connected = 0;
	(*ppfi)->tcp_seq= tcp_seq;
	init_slist(&(*ppfi)->data_list, fd_packet_cmp);
}

void destroy_fd_info(fd_info_t **ppfi)
{
	destroy_slist(&(*ppfi)->data_list, 1);
	free(*ppfi);
}
