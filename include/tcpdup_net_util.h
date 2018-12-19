#pragma once
#include "tcpdup_container.h"

void set_fd_nonblock(int fd); 

typedef struct fd_packet {
    unsigned int tcp_seq;
    int is_fin;
    int packet_len;
    char packet[0];
} fd_packet_t;

typedef struct fd_info {
    int fd; 
    char ipport[6];
    int connected;//nonblock connect
    unsigned int tcp_seq;
    sorted_list_t *data_list;
} fd_info_t;

void init_fd_info(fd_info_t **ppfi, int fd, char *ipport, unsigned int tcp_seq);

void destroy_fd_info(fd_info_t **ppfi);

