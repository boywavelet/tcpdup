#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/ip.h>

void str_cli(int sock) 
{
	char sendbuffer[100];
	char recvbuffer[100];
	while(scanf("%s", sendbuffer)) {
		printf("LEN:%d:%s\n", strlen(sendbuffer), sendbuffer);
		write(sock, sendbuffer, strlen(sendbuffer));
		//int rsz = read(sock, recvbuffer, 100);
		//printf("##%d\n", rsz, recvbuffer);
		//int i = 0;
		//for (i = 0; i < rsz; ++i) {
		//	printf("%c", recvbuffer[i]);
		//}
	}
}

void str_cli2(int sock) 
{
	char sendbuffer[100];
	char sendbuffer2[100];
	sprintf(sendbuffer2, "%s", "suffix");
	struct iovec iov[2];
	while(scanf("%s", sendbuffer)) {
		printf("LEN:%d:%s\n", strlen(sendbuffer), sendbuffer);
		iov[0].iov_base = sendbuffer;
		iov[0].iov_len = strlen(sendbuffer);
		iov[1].iov_base = sendbuffer2;
		iov[1].iov_len = strlen(sendbuffer2);
		writev(sock, iov, 2);
	}
}

int main() 
{
	char *ip = "10.23.53.150";
	int port = 23456;

	int sock = socket(AF_INET, SOCK_STREAM, 0);

	struct sockaddr_in server_addr;
	bzero(&server_addr, sizeof(server_addr));

	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port);

	inet_pton(AF_INET, ip, &server_addr.sin_addr);

	int ret = connect(sock, (const struct sockaddr *)&server_addr, sizeof(server_addr));
	if (ret != 0) {
		perror("connect failed");
		exit(1);
	}

	str_cli2(sock);

	close(sock);

	return 0;
}
