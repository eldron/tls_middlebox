#include <stdio.h>
#include <unistd.h>
#include "mb_parse_tls_13.h"

int main(){
    FILE * fin = fopen("client_hello.raw", "r");
    if(!fin){
        fprintf(stderr, "can not open file client_hello.raw");
        return 1;
    } else {
        fprintf(stderr, "opended file client_hello.raw\n");
    }
    // test file should be smaller than 10000 bytes
    uint8_t * buffer = (uint8_t *) malloc(10000);
    int fd = fileno(fin);
    uint32_t length = read(fd, buffer, 10000);
    fprintf(stderr, "client hello file length = %u\n", length);
    struct client_hello_str * client_hello;
    uint8_t content_type;
    uint32_t handshake_type;
    SECStatus rv = parse_record((PRUint8 **) &buffer, 
        (PRUint32) length, &content_type, &handshake_type, (void **) &client_hello);
    fprintf(stderr, "client hello parse record completed\n");
    if(rv == SECFailure){
        fprintf(stderr, "error parsing file client_hello.raw\n");
        fclose(fin);
        return 1;
    }
    print_extensions(&(client_hello->ext_list));
    fclose(fin);

    fin = fopen("server_hello.raw", "r");
    if(!fin){
        fprintf(stderr, "can not open file server_hello.raw\n");
        return 1;
    }
    fd = fileno(fin);
    length = read(fd, buffer, 10000);
    struct server_hello_str * server_hello;
    rv = parse_record((PRUint8 **) &buffer, 
        (PRUint32) length, &content_type, &handshake_type, (void **) &server_hello);
    if(rv == SECFailure){
        fprintf(stderr, "error parsing file server_hello.raw\n");
        fclose(fin);
        return 1;
    }
    print_extensions(&(server_hello->ext_list));
    fclose(fin);

    return 0;
}
