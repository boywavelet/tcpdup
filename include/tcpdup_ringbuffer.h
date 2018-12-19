#pragma once
#include <pthread.h>
#include <pcap.h>

struct pcap_pkthdr;

//add a whole history data offset
//three index, read_pos, write_pos, ack_pos

//MAYBE: data alignment
typedef struct ring_buffer {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    int read_pos;
    int write_pos;
    int size;
    unsigned char data[0];
}ring_buffer_t;

int init_ringbuffer(ring_buffer_t **pprb, int buffer_size);

void destroy_ringbuffer(ring_buffer_t **pprb);

int is_ringbuffer_empty(ring_buffer_t *prb); 

int can_read_ringbuffer(ring_buffer_t *prb); 

int get_ringbuffer_avail_write_size(ring_buffer_t *prb); 
int get_ringbuffer_avail_read_size(ring_buffer_t *prb);

int ringbuffer_write(ring_buffer_t* prb, const void* data, int len); 

int ringbuffer_write2(
        ring_buffer_t* prb, 
        const void* head, int head_len, 
        const void* data, int data_len); 

int ringbuffer_lock_write2(
        ring_buffer_t* prb, 
        const void* head, int head_len, 
        const void* data, int data_len); 

int ringbuffer_read(ring_buffer_t* prb, void *data, int len); 
int ringbuffer_unread(ring_buffer_t* prb, int len); 

int ringbuffer_lock_read2(
		ring_buffer_t* prb,
		struct pcap_pkthdr *pkthdr,
		void *data, int *data_len);

