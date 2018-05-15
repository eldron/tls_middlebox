#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char ** args){
    if(argc != 3){
        fprintf(stderr, "usage: %s server_address server_port\n", args[0]);
        return 0;
    }

	int client_fd;
	struct sockaddr_in dest;
	client_fd = socket(AF_INET, SOCK_STREAM, 0);
	memset(&dest, 0, sizeof(dest));
	dest.sin_family = AF_INET;
	dest.sin_addr.s_addr = inet_addr(args[1]);
	dest.sin_port = htons(atoi(args[2]));
	if(connect(client_fd, (struct sockaddr *) &dest, sizeof(struct sockaddr_in)) < 0){
		fprintf(stderr, "connect error\n");
		exit(1);
	} else {
		fprintf(stderr, "connected to server\n");
	}
    
    char client_msg[2000];
    int len = recv(client_fd, client_msg , 2000 , 0);
    if(len > 0){
        fprintf(stderr, "receoved %d bytes from server\n", len);
        fprintf(stderr, "%s\n", client_msg);
    }
	close(client_fd);

	return 0;
}