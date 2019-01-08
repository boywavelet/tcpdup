#include "tcpdup_net_util.h"
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include "tcpdup_util.h"

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
	(*ppfi)->connected = connected;
	(*ppfi)->closed = 0;
	(*ppfi)->stat_total_write = 0;
	(*ppfi)->stat_num_packet = 0;
	(*ppfi)->tcp_seq= tcp_seq;
	(*ppfi)->last_active_time = get_current_milliseconds();
	init_linked_list(&(*ppfi)->time_list);
	init_slist(&(*ppfi)->data_list, fd_packet_cmp);
}

void destroy_fd_info(fd_info_t **ppfi)
{
	linked_list_del(&(*ppfi)->time_list);
	destroy_slist(&(*ppfi)->data_list, 1);
	free(*ppfi);
}

void* fd_info_emplace_data(
		fd_info_t *pfi, void* data, int len, 
		unsigned int tcp_seq, int is_fin) 
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
	pfi->stat_num_packet++;
	return fp;
}

void* fd_info_append_fin(fd_info_t *pfi)
{
	fd_packet_t *last_pack = (fd_packet_t *)slist_peek_last(pfi->data_list);
	unsigned int tcp_seq = pfi->tcp_seq + 1;
	if (last_pack != NULL && last_pack->is_fin) {
		//already there
		return last_pack;
	}
	if (last_pack != NULL) {
		tcp_seq = last_pack->tcp_seq + last_pack->packet_len;
	}
	return fd_info_emplace_data(pfi, NULL, 0, tcp_seq, 1);
}

//BEGIN: expect_seq = fd_info->tcp_seq + 1 
int if_packet_consecutive(void *payload, void *arg) 
{
	fd_packet_t *packet = (fd_packet_t *)payload;
	int *expect_seq = (int *)arg;
	if (packet->tcp_seq != *expect_seq) {
		return 0;
	}
	*expect_seq += packet->packet_len;
	return 1;
}

int fd_info_is_consecutive(fd_info_t *pfi)
{
	int expect_seq = pfi->tcp_seq + 1;
	return slist_readonly_iter(pfi->data_list, if_packet_consecutive, &expect_seq);
}

int write_packet_data(void *payload, void *arg)
{
	fd_packet_t *packet = (fd_packet_t *)payload;
	fd_info_t *pfi = (fd_info_t *)arg;
	if (!pfi->connected || pfi->closed) {
		return 0;
	}
	if (pfi->tcp_seq + 1 != packet->tcp_seq) {
		return 0;
	}
	//MAYBE: packet may contain both fin|rst and data
	if (packet->is_fin) {
		pfi->connected = 0;
		pfi->closed = 1;
		return 0;
	}
	int write_ret = write(pfi->fd, packet->data, packet->packet_len);
	if (write_ret == packet->packet_len) {
		pfi->stat_total_write += write_ret;
		pfi->tcp_seq += write_ret;
		//all the payload consumed
		free(payload);
		pfi->stat_num_packet--;
		return 1;
	} else if (write_ret > 0) {
		pfi->stat_total_write += write_ret;
		packet->data += write_ret;
		packet->tcp_seq += write_ret;
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

int is_fd_info_has_writable_data(fd_info_t *pfi)
{
	if (is_slist_empty(pfi->data_list)) {
		return 0;
	}
	fd_packet_t *packet = (fd_packet_t *)slist_peek_first(pfi->data_list);
	if (pfi->tcp_seq + 1 == packet->tcp_seq) {
		return 1;
	} else {
		return 0;
	}
}

void fd_info_touch(
		fd_info_t *pfi, 
		long current_time, 
		linked_list_t *time_list_head)
{
	pfi->last_active_time = current_time;
	linked_list_move_tail(&pfi->time_list, time_list_head);
}

