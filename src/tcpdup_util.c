#include "tcpdup_util.h"
#include <sys/time.h>
#include <stdlib.h>

long get_current_milliseconds() 
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	long result = ((long)tv.tv_sec) * 1000 + ((long)tv.tv_usec) / 1000; 
	return result;
}
