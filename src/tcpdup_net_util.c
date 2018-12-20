#include "tcpdup_net_util.h"
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

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

void init_fd_info(
		fd_info_t **ppfi, 
		int fd, char *ipport, 
		int connected, unsigned int tcp_seq)
{
	*ppfi = malloc(sizeof(fd_info_t));
	(*ppfi)->fd = fd;
	memcpy((*ppfi)->ipport, ipport, 6);
	(*ppfi)->connected = 0;
	(*ppfi)->closed = 0;
	(*ppfi)->tcp_seq= tcp_seq;
	init_slist(&(*ppfi)->data_list, fd_packet_cmp);
}

void destroy_fd_info(fd_info_t **ppfi)
{
	destroy_slist(&(*ppfi)->data_list, 1);
	free(*ppfi);
}

void* fd_info_emplace_data(fd_info_t *pfi, void* data, int len, int tcp_seq, int is_fin) 
{
	int size = sizeof(fd_packet_t) + len;
	fd_packet_t *fp = malloc(size);
	memset(fp, 0, size);
	
	fp->tcp_seq = tcp_seq;
	fp->is_fin = is_fin;
	fp->packet_len = len;
	memcpy(fp->packet, data, len);
	fp->data = fp->packet;
	slist_insert(pfi->data_list, fp);
	return fp;
}

int write_packet_data(void *payload, void *arg)
{
	fd_packet_t *packet = (fd_packet_t *)packet;
	fd_info_t *pfi = (fd_info_t *)arg;
	if (!pfi->connected || pfi->closed) {
		return 0;
	}
	if (pfi->tcp_seq + 1 != packet->tcp_seq) {
		return 0;
	}
	int write_ret = write(pfi->fd, packet->data, packet->packet_len);
	if (write_ret == packet->packet_len) {
		pfi->tcp_seq += write_ret;
		//free payload
		free(payload);
		return 1;
	} else if (write_ret > 0) {
		packet->data += write_ret;
		packet->packet_len -= write_ret;
		pfi->tcp_seq += write_ret;
		return 0;
	} else /*write_ret <= 0*/{
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			//just do nothing, wait for next writable timing
		} else {
			//outer caller will process clean-task, including close fd
			pfi->connected = 0;
			pfi->closed = 1; 
		}
		return 0;
	}
}

void fd_info_write_data(fd_info_t *pfi)
{
	slist_oneshot_iter(pfi->data_list, write_packet_data, pfi);
}



