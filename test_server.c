#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

/*
 * This will handle connection for each client
 * */
void * connection_handler(void *socket_desc)
{
    //Get the socket descriptor
    int sock = *(int*)socket_desc;
    int read_size;
    char *message , client_message[2000];
     
    //Send some messages to the client
    message = "Greetings! I am your connection handler\n";
    write(sock , message , strlen(message));
     
    // message = "Now type something and i shall repeat what you type \n";
    // write(sock , message , strlen(message));
     
    // //Receive a message from client
    // while( (read_size = recv(sock , client_message , 2000 , 0)) > 0 )
    // {
    //     //end of string marker
	// 	client_message[read_size] = '\0';
		
	// 	//Send the message back to client
    //     write(sock , client_message , strlen(client_message));
		
	// 	//clear the message buffer
	// 	memset(client_message, 0, 2000);
    // }
     
    // if(read_size == 0)
    // {
    //     puts("Client disconnected");
    //     fflush(stdout);
    // }
    // else if(read_size == -1)
    // {
    //     perror("recv failed");
    // }
         
    return 0;
} 

int main(int argc, char ** args){
	if(argc != 2){
		fprintf(stderr, "usage: %s port\n", args[0]);
		return 0;
	}

	// create server socket
	int server_socket_fd;
	int client_socket_fd;
	struct sockaddr_in server_address;
	struct sockaddr_in client_address;
	unsigned int server_port = atoi(args[1]);
	if((server_socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0){
		fprintf(stderr, "create server socket failed\n");
		return 0;
	} else {
		fprintf(stderr, "created server socket\n");
	}
	memset(&server_address, 0, sizeof(server_address));
	server_address.sin_family = AF_INET;
	server_address.sin_addr.s_addr = htonl(INADDR_ANY);
	server_address.sin_port = htons(server_port);
	// bind to the local address
	if(bind(server_socket_fd, (struct sockaddr *) &server_address, sizeof(server_address)) < 0){
		fprintf(stderr, "bind server socket failed\n");
		return 0;
	} else {
		fprintf(stderr, "binded server socket\n");
	}
	// listen for the incoming connection
	if(listen(server_socket_fd, 10) < 0){
		fprintf(stderr, "listen server socket failed\n");
		return 0;
	}

    pthread_t thread_id;
    while(1){
        unsigned int client_address_len = sizeof(client_address);
        if((client_socket_fd = accept(server_socket_fd, (struct sockaddr *) &client_address, &client_address_len)) < 0){
            fprintf(stderr, "accept client connection failed\n");
            return 0;
        }
        fprintf(stderr, "accepted client connection\n");
        // create thread to handle this client connection
        if(pthread_create(&thread_id, NULL, connection_handler, (void *) &client_socket_fd) != 0){
            fprintf(stderr, "create thread failed\n");
            return 1;
        }
        fprintf(stderr, "handler assigned\n");
    }

	return 0;
}
