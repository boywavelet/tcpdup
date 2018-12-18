#include "net_util.h"
#include <fcntl.h>

void set_fd_nonblock(int fd) 
{
	int flags = fcntl(fd, F_GETFL, 0); 
	fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

