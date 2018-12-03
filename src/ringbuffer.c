#include "ringbuffer.h"
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>

int init_ringbuffer(ring_buffer_t **pprb, int buffer_size) 
{
	int buffer_malloc_size = sizeof(ring_buffer_t) + buffer_size;
	*pprb = malloc(buffer_malloc_size);
	memset(*pprb, 0, buffer_malloc_size);
	madvise(*pprb, buffer_malloc_size, MADV_DONTDUMP);
	pthread_mutex_init(&(*pprb)->mutex, NULL);
	pthread_cond_init(&(*pprb)->cond, NULL);
	(*pprb)->size = buffer_size;
	return 0;
}

void destroy_ringbuffer(ring_buffer_t **pprb)
{
	pthread_cond_destroy(&(*pprb)->cond);
	pthread_mutex_destroy(&(*pprb)->mutex);
	free(*pprb);
}

int is_ringbuffer_empty(ring_buffer_t *prb) 
{
	return prb->read_pos == prb->write_pos;
}

int can_read_ringbuffer(ring_buffer_t *prb) 
{
	return prb->write_pos != prb->read_pos;
}

int get_ringbuffer_avail_size(ring_buffer_t *prb) 
{
	int write_pos = prb->write_pos;
	int read_pos = prb->read_pos;
	int size = prb->size;

	if (write_pos < read_pos) {
		return read_pos - write_pos;
	} else {
		return size - (write_pos - read_pos);
	}
}

int ringbuffer_write(ring_buffer_t* prb, const void* data, int len) 
{
	if (len > get_ringbuffer_avail_size(prb)) {
		return -1;
	}
	int write_pos = prb->write_pos;
	int size = prb->size;
	if (write_pos + len < size) {
		memcpy(prb->data + write_pos, data, len);
		prb->write_pos += len;
	} else {
		memcpy(prb->data + write_pos, data, size - write_pos);
		memcpy(prb->data, data + (size - write_pos), len - (size - write_pos));
		prb->write_pos = len - (size - write_pos);
	}
	return 0;
}

int ringbuffer_write2(
        ring_buffer_t* prb, 
        const void* head, int head_len, 
        const void* data, int data_len) 
{
	if (head_len + data_len > get_ringbuffer_avail_size(prb)) {
		return -1;
	}
	ringbuffer_write(prb, head, head_len);
	ringbuffer_write(prb, data, data_len);
	return 0;
}

int ringbuffer_lock_write2(
        ring_buffer_t* prb, 
        const void* head, int head_len, 
        const void* data, int data_len) 
{
	pthread_mutex_lock(&prb->mutex);
	int ret = ringbuffer_write2(prb, head, head_len, data, data_len);
	pthread_cond_signal(&prb->cond);
	pthread_mutex_unlock(&prb->mutex);
	return ret;
}

int ringbuffer_read(ring_buffer_t* prb, void *data, int len) 
{
	int read_pos = prb->read_pos;
	int size = prb->size;
	if (read_pos + len < size) {
		memcpy(data, prb->data + read_pos, len);
		prb->read_pos += len;
	} else {
		memcpy(data, prb->data + read_pos, size - read_pos);
		memcpy(data + (size - read_pos), prb->data, len - (size - read_pos));
		prb->read_pos = len - (size - read_pos);
	}

	return 0;
}

int ringbuffer_lock_read2(
		ring_buffer_t* prb,
		struct pcap_pkthdr *pkthdr,
		void *data, int *data_len)
{
	pthread_mutex_lock(&prb->mutex);
	while (!can_read_ringbuffer(prb)) {
		pthread_cond_wait(&prb->cond, &prb->mutex);
	}
	ringbuffer_read(prb, pkthdr, sizeof(struct pcap_pkthdr));
	*data_len = pkthdr->len;
	ringbuffer_read(prb, data, *data_len);
	pthread_mutex_unlock(&prb->mutex);
	return 0;
}


