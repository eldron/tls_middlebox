#include <stdio.h> 
#include <string.h>   //strlen 
#include <stdlib.h> 
#include <errno.h> 
#include <unistd.h>   //close 
#include <arpa/inet.h>    //close 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <netinet/in.h> 
#include <sys/time.h> //FD_SET, FD_ISSET, FD_ZERO macros 
#include <pthread.h>
#include <netdb.h>
#include <stdint.h>

#include "mb_parse_tls_13.h"

// later we should replace malloc with customized memory management functions

struct memory_pool{
    char * data;
    uint32_t idx;
    uint32_t length; // max length of this memory pool
};

struct memory_pool mem_pool;

char * memory_pool_malloc(struct memory_pool * pool, uint32_t len){
    if(pool->idx + len > pool->length){
        return NULL;
    } else {
        uint32_t tmp = pool->idx;
        pool->idx += len;
        return &(pool->data[pool->idx]);
    }
}

typedef enum{
    // initial state, waiting for client hello
    // when received client hello, jump to state mb_wait_server_hello
    mb_wait_client_hello,

    // wait for server hello
    // when received server hello, jump to state mb_handshake_done
    // when received hello retry, jump to state mb_wait_client_hello
    mb_wait_server_hello,

    // handshake is done
    mb_handshake_done
} MBState;

struct MBTLSConnection{
    MBState state;
    int client_socket_fd;
    int server_socket_fd;

    struct client_hello_str * client_hello;
    struct server_hello_str * server_hello;

    // compute and store master secret, early_traffic_secret, traffic_secret, etc
};

void print_auth_method(unsigned char method){
    printf("authentication method is: ");
    if(method == 0){
        printf("no authentication required\n");
    } else if(method == 1){
        printf("gssapi\n");
    } else if(method == 2){
        printf("username password\n");
    } else if(3 <= method && method <= 0x7f){
        printf("IANA assigned\n");
    } else if(0x80 <= method && method <= 0xfe){
        printf("reserved for private methods\n");
    } else {
        printf("no acceptable methods\n");
    }
}

void parse_method_selection_msg(unsigned char * msg){
    unsigned int version = (unsigned int) msg[0];
    unsigned int number_of_methods = (unsigned int) msg[1];
    printf("version  = %u\n", version);
    printf("number of authentication methods = %u\n", number_of_methods);

    int i;
    for(i = 0;i < number_of_methods;i++){
        print_auth_method(msg[i + 2]);
    }
}

void forward_data(int one, int another){
    fd_set read_fds;
    char buffer[2048];
    int len;

    printf("forward_data is called\n");
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    int big;
    if(one > another){
        big = one;
    } else {
        big = another;
    }

    while(1){
        FD_ZERO(&read_fds);
        FD_SET(one, &read_fds);
        FD_SET(another, &read_fds);

        int number_of_active_fd = select(big + 1, &read_fds, NULL, NULL, NULL);
        fprintf(stderr, "number of active fds is %d\n", number_of_active_fd);
        if(number_of_active_fd < 0){
            fprintf(stderr, "forward_data: select error\n");
            close(one);
            close(another);
            return;
        } else {
            if(FD_ISSET(one, &read_fds)){
                // read from one, send to another
                len = read(one, buffer, 2048);
                if(len <= 0){
                    // close the sockets
                    close(one);
                    close(another);
                    return;
                } else {
                    printf("forward_data: read from one, send to another\n");
                    write(another, buffer, len);
                }
            } else {
                fprintf(stderr, "one is not set\n");
            }

            if(FD_ISSET(another, &read_fds)){
                // read from another, send to one
                len = read(another, buffer, 2048);
                if(len <= 0){
                    // close the sockets
                    close(one);
                    close(another);
                    return;
                } else {
                    printf("forward_data: read from another, send to one\n");
                    write(one, buffer, len);
                }
            } else {
                fprintf(stderr, "another is not set\n");
            }
        }
    }
}

// when received the first clieht hello, middlebox record A_{1}
// when received the n'th client hello, middlebox record A_{n}
// when received the n'th server hello, middlebox compute a_{n} = A_{n-1}^alpha
// when received application data, try to decrypt and do DPI
void asymmetric_inspect(int client_fd, int server_fd){
    fd_set read_fds;
    //char buffer[2048];
    //char * buffer = memory_pool_malloc(&mem_pool, 2048);
    struct MBTLSConnection conn;
    conn.state = mb_wait_client_hello;
    conn.client_socket_fd = client_fd;
    conn.server_socket_fd = server_fd;

    //int len;
    int big;
    if(client_fd > server_fd){
        big = client_fd;
    } else {
        big = server_fd;
    }

    // record the TLS handshake state
    while(1){
        FD_ZERO(&read_fds);
        FD_SET(client_fd, &read_fds);
        FD_SET(server_fd, &read_fds);

        int number_of_active_fd = select(big + 1, &read_fds, NULL, NULL, NULL);
        if(number_of_active_fd < 0){
            fprintf(stderr, "forward_data: select error\n");
            close(client_fd);
            close(server_fd);
            return;
        } else {
            if(FD_ISSET(client_fd, &read_fds)){
                // read from client, send to server
                if(conn.state == mb_wait_client_hello || conn.state == mb_wait_server_hello){
                    char * buffer = memory_pool_malloc(&mem_pool, 2048);
                    uint32_t length = read(client_fd, buffer, 2048);
                    char * tmp_buf = buffer;
                    uint32_t tmp_length = length;
                    if(length <= 0){
                        // close the sockets
                        close(client_fd);
                        close(server_fd);
                        return;
                    }

                    uint8_t content_type;
                    uint32_t handshake_type;
                    void * content_struct;
                    SECStatus rv = parse_record((PRUint8 **) &buffer, (PRUint32) length, 
                        &content_type, &handshake_type, &content_struct);
                    
                    if(conn.state == mb_wait_client_hello){
                        if(content_type == content_handshake && handshake_type == ssl_hs_client_hello){
                            // received client hello
                            conn.state = mb_wait_server_hello;
                            conn.client_hello = (struct client_hello_str *) *content_struct;
                            // extract and store public key

                        } else {
                            fprintf(stderr, "asymmetric_inspect: unexpected packet\n");
                        }
                    } else {
                        if(content_type == content_handshake && handshake_type == ssl_hs_server_hello){
                            // received server hello
                            conn.state = mb_handshake_done;
                            conn.server_hello = (struct server_hello_str *) *content_struct;
                            // compute handshake secrets
                            
                        } else {
                            fprintf(stderr, "asymmetric_inspect: unexpected packet\n");
                        }
                    }
                    // send data to server
                    write(server_fd, tmp_buf, tmp_length);
                } else if(conn.state == mb_handshake_done){

                }
                // uint32_t len = read(client_fd, buffer, 2048);
                // if(len <= 0){
                //     // close the sockets
                //     close(client_fd);
                //     close(server_fd);
                //     return;
                // } else {
                //     printf("forward_data: read from one, send to another\n");
                //     write(server_fd, buffer, len);
                // }
            } else {
                //fprintf(stderr, "one is not set\n");
            }

            if(FD_ISSET(server_fd, &read_fds)){
                // read from server, send to client
                len = read(server_fd, buffer, 2048);
                if(len <= 0){
                    // close the sockets
                    close(client_fd);
                    close(server_fd);
                    return;
                } else {
                    printf("forward_data: read from another, send to one\n");
                    write(client_fd, buffer, len);
                }
            } else {
                //fprintf(stderr, "another is not set\n");
            }
        }
    }
}
void * handle_connection(void * sock){
    int client_fd = *(int *) sock;
    int len;
    unsigned char buffer[2048];

    // receive version and authentication methods
    len = read(client_fd, buffer, 2048);
    if(len <= 0){
        fprintf(stderr, "handle_connection: read socket error\n");
        return NULL;
    }
    parse_method_selection_msg(buffer);

    // currently only support no authentication, send selected authentication method
    char method_bytes[] = {0x05, 0x00};
    write(client_fd, method_bytes, 2);

    // receive request details
    len = read(client_fd, buffer, 2048);
    if(len <= 0){
        fprintf(stderr, "handle_connection: error reading request details\n");
        return NULL;
    }
    unsigned int version_number = buffer[0];
    unsigned int cmd = buffer[1];
    unsigned int address_type = buffer[3];
    struct sockaddr_in requested_addr;// the sin_port and sin_addr member must be represented in big endian
    memset(&requested_addr, 0, sizeof(requested_addr));

    if(cmd == 1){
        // we only support this
        if(address_type == 1){
            // ipv4
            // the next 4 bytes are ipv4 address
            requested_addr.sin_family = AF_INET;
            memcpy(&(requested_addr.sin_addr.s_addr), &(buffer[4]), 4);
            // the next 2 bytes are port number in big endian
            memcpy(&(requested_addr.sin_port), &(buffer[8]), 2);
        } else if(address_type == 3){
            // domain name
            // the first byte contains the domain name length
            int domain_name_length = (int) buffer[4];
            struct addrinfo * result; // to store results
            struct addrinfo hints;// to indicate information we want
            memset(&hints, 0, sizeof(struct addrinfo));
            hints.ai_family = AF_INET;
            char * domain_name = (char *) malloc(domain_name_length + 1);
            memset(domain_name, '\0', domain_name_length);
            memcpy(domain_name, &(buffer[5]), domain_name_length);
            int s = getaddrinfo(domain_name, NULL, &hints, &result);
            printf("handle_connection: address type is domain name\ndomain name is %s\n", domain_name);
            free(domain_name);
            if(s != 0){
                fprintf(stderr, "handle_connection: getaddrinfo error\n");
                return NULL;
            }
            memcpy(&requested_addr, result->ai_addr, sizeof(struct sockaddr_in));
            freeaddrinfo(result);
            // the next 2 bytes are port number in big endian
            memcpy(&(requested_addr.sin_port), &(buffer[5 + domain_name_length]), 2);
        } else if(address_type == 4){
            // ipv6
            char failed_reply[] = {0x05, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
            write(client_fd, failed_reply, sizeof(failed_reply));
        } else {
            fprintf(stderr, "unexpected address type\n");
            char failed_reply[] = {0x05, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
            write(client_fd, failed_reply, sizeof(failed_reply));
        }

        // try to connected to the requested host
        // if connected, send connection established to client
        // else send failed reply to the client
        int target_sock_fd = socket(AF_INET, SOCK_STREAM, 0);
        int connected = connect(target_sock_fd, (struct sockaddr *) &requested_addr, sizeof(struct sockaddr_in));
        if(connected < 0){
            printf("handle_connection: failed connection with remote host\n");
            char failed_reply[] = {0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
            write(client_fd, failed_reply, sizeof(failed_reply));
        } else {
            printf("handle_connection: connection with remote host succeeded\n");
            char succeeded_reply[10];
            succeeded_reply[0] = 0x05;
            succeeded_reply[1] = 0x00;
            succeeded_reply[2] = 0x00;
            succeeded_reply[3] = 0x01;
            struct sockaddr_in tmpaddr;
            memset(&tmpaddr, 0, sizeof(struct sockaddr_in));
            int tmplen = sizeof(struct sockaddr_in);
            getsockname(target_sock_fd, (struct sockaddr *) &tmpaddr, &tmplen);
            memcpy(&(succeeded_reply[4]), &(tmpaddr.sin_addr.s_addr), 4);
            memcpy(&(succeeded_reply[8]), &(tmpaddr.sin_port), 2);
            write(client_fd, succeeded_reply, sizeof(succeeded_reply));

            // forward data
            forward_data(client_fd, target_sock_fd);
        }
    } else {
        // send failed reply to client
        char failed_reply[] = {0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        write(client_fd, failed_reply, sizeof(failed_reply));
    }
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
        if(pthread_create(&thread_id, NULL, handle_connection, (void *) &client_socket_fd) != 0){
            fprintf(stderr, "create thread failed\n");
            return 1;
        }
        fprintf(stderr, "handler assigned\n");
    }

	return 0;
}