#include "mb_parse_tls_13.h"

int main(){
    char * filename = "client_hello.raw";
    FILE * fin = fopen(filename, "r");
    if(!fin){
        fprintf(stderr, "can not open file %s\n", filename);
        return 1;
    }
    // test file should be smaller than 10000 bytes
    char buffer[10000];
    int fd = fileno(fin);
    uint32_t length = read(fd, buffer, 10000);
    struct client_hello_str client_hello;
    uint8_t content_type;
    uint32_t handshake_type;
    SECStatus rv = parse_record(&buffer, length, &content_type, &handshake_type, &client_hello);
    if(rv == SECFailure){
        fprintf(stderr, "error parsing file client_hello.raw\n");
        fclose(fin);
        return 1;
    }
    print_extensions(&(client_hello.ext_list));
    fclose(fin);

    fin = fopen("server_hello.raw", "r");
    if(!fin){
        fprintf(stderr, "can not open file server_hello.raw\n");
        return 1;
    }
    fd = fileno(fin);
    length = read(fd, buffer, 10000);
    struct server_hello_str server_hello;
    SECStatus rv = parse_record(&buffer, length, &content_type, &handshake_type, &server_hello);
    if(rv == SECFailure){
        fprintf(stderr, "error parsing file server_hello.raw\n");
        fclose(fin);
        return 1;
    }
    print_extensions(&(server_hello->ext_list));
    fclose(fin);

    return 0;
}
