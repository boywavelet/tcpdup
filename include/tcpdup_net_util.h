#pragma once
#include "tcpdup_container.h"

void set_fd_nonblock(int fd); 

typedef struct fd_packet {
    unsigned int tcp_seq;
    int is_fin;
    void *data;
    int packet_len;
    char packet[0];
} fd_packet_t;

typedef struct fd_info {
    int fd; 
    char ipport[6];
    int connected;//nonblock connect
    int closed;
    int stat_total_write;
    int stat_num_packet;
    unsigned int tcp_seq;
    sorted_list_t *data_list;
} fd_info_t;

void init_fd_info(
		fd_info_t **ppfi, 
		int fd, char *ipport, 
		int connected, unsigned int tcp_seq);

void destroy_fd_info(fd_info_t **ppfi);

//return fd_packet_t*
void* fd_info_emplace_data(
        fd_info_t *pfi, 
        void* data, int len, 
        unsigned int tcp_seq, int is_fin); 

void fd_info_write_data(fd_info_t *pfi);

int is_fd_info_has_writable_data(fd_info_t *pfi);

