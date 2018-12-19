#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/ip.h>

void str_echo(int sockfd)
{
	int len = 0;
	char buf[2048];
	while ((len = read(sockfd, buf, 2000)) > 0) {
		int i;
again:
		printf("Read:%d\n", len);
		for (i = 0; i < len; ++i) {
			if (isprint(buf[i])) {
				printf("%c", buf[i]);
			}
		}
		printf("\n");
		//write(sockfd, buf, len);
	}

	if (len < 0 && errno == EINTR) {
		goto again;
	} else if (len < 0) {
		printf("read error\n");
		close(sockfd);
		exit(200);
	} else if (len == 0) {
		printf("read exit\n");
		close(sockfd);
		exit(0);
	}
}

int main() 
{
	int listenfd, connfd;
	pid_t childpid;

	socklen_t clilen;
	struct sockaddr_in cliaddr, servaddr;

	listenfd = socket(AF_INET, SOCK_STREAM, 0);
	int enable = 1;
	setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(23456);

	bind(listenfd, (const struct sockaddr *)&servaddr, sizeof(servaddr));
	listen(listenfd, 512);

	while (1) {
		clilen = sizeof(cliaddr);
		connfd = accept(listenfd, (struct sockaddr *)&cliaddr, &clilen);

		if ((childpid = fork()) == 0) {
			close(listenfd);
			str_echo(connfd);
		} else {
			close(connfd);
		}
	}

	return 0;
}
