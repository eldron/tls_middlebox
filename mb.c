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

#include "sslt.h" // /nss/lib/ssl/sslt.h
#include "ssl3ext.h" // /nss/lib/ssl/ssl3ext.h
#include "prclist.h" // /nspr/pr/include/prclist.h

#define CLIENT_HELLO_RANDOM_LENGTH 32
#define SESSION_ID_LENGTH 32

// later we should replace malloc with customized memory management functions


char * get_ext_name(uint16_t type){
    switch(type){
        case ssl_server_name_xtn:
        return "server_name_xtn";
        case ssl_cert_status_xtn:
        return "cert_status_xtn";
        case ssl_supported_groups_xtn:
            return "supported_groups_xtn";
        case ssl_ec_point_formats_xtn:
            return "ec_point_formats_xtn";
        case ssl_signature_algorithms_xtn:
            return "signature_algorithms_xtn";
        case ssl_use_srtp_xtn:
            return "use_srtp_xtn";
        case ssl_app_layer_protocol_xtn:
            return "app_layer_protocol_xtn";
        case ssl_signed_cert_timestamp_xtn:
            return "signed_cert_timestamp_xtn";
        case ssl_padding_xtn:
            return "padding_xtn";
        case ssl_extended_master_secret_xtn:
            return "extended_master_secret_xtn";
        case ssl_session_ticket_xtn:
            return  "session_ticket_xtn";
        case ssl_tls13_pre_shared_key_xtn:
            return "tls13_pre_shared_key_xtn";
        case ssl_tls13_early_data_xtn:
            return "tls13_early_data_xtn";
        case ssl_tls13_supported_versions_xtn:
            return "tls13_supported_versions_xtn";
        case ssl_tls13_cookie_xtn:
            return "tls13_cookie_xtn";
        case ssl_tls13_psk_key_exchange_modes_xtn:
            return "tls13_psk_key_exchange_modes_xtn";
        case ssl_tls13_ticket_early_data_info_xtn:
            return "tls13_ticket_early_data_info_xtn";
        case ssl_tls13_certificate_authorities_xtn:
            return "tls13_certificate_authorities_xtn";
        case ssl_signature_algorithms_cert_xtn:
            return "signautre_algorithms_cert";
        case ssl_tls13_key_share_xtn:
            return "tls13_key_share_xtn";
        case ssl_next_proto_nego_xtn:
            return "next_proto_nego_xtn";
        case ssl_renegotiation_info_xtn:
            return "renegotiation_info_xtn";
        case ssl_tls13_short_header_xtn:
            return "tls13_short_header_xtn";
        default:
            return "unknown extension";
    }

    return "unknown extension";
}
// consume handshake functions copied from ssl3cons.c

/* Read up the next "bytes" number of bytes from the (decrypted) input
 * stream "b" (which is *length bytes long). Copy them into buffer "v".
 * Reduces *length by bytes.  Advances *b by bytes.
 *
 * If this function returns SECFailure, it has already sent an alert,
 * and has set a generic error code.  The caller should probably
 * override the generic error code by setting another.
 */
SECStatus
ssl3_ConsumeHandshake(void *v, PRUint32 bytes, PRUint8 **b,
                      PRUint32 *length){

    if ((PRUint32)bytes > *length) {
        fprintf(stderr, "ssl3_ConsumeHandshake: bytes larger than length\n");
        return SECFailure;
    }
    PORT_Memcpy(v, *b, bytes);
    *b += bytes;
    *length -= bytes;
    return SECSuccess;
}
/* Read up the next "bytes" number of bytes from the (decrypted) input
 * stream "b" (which is *length bytes long), and interpret them as an
 * integer in network byte order.  Sets *num to the received value.
 * Reduces *length by bytes.  Advances *b by bytes.
 *
 * On error, an alert has been sent, and a generic error code has been set.
 */
SECStatus
ssl3_ConsumeHandshakeNumber64(PRUint64 *num, PRUint32 bytes,
                              PRUint8 **b, PRUint32 *length)
{
    PRUint8 *buf = *b;
    PRUint32 i;
    *num = 0;
    if (bytes > sizeof(*num)) {
        //PORT_SetError(SEC_ERROR_LIBRARY_FAILURE);
        fprintf(stderr, "ssl3_ConsumeHandshakeNumber64: bytes larger than size of *num\n");
        return SECFailure;
    }

    if (bytes > *length) {
        fprintf(stderr, "ssl3_ConsumeHandshakeNumber64: bytes larger than *length\n");
        return SECFailure;
    }

    for (i = 0; i < bytes; i++) {
        *num = (*num << 8) + buf[i];
    }
    *b += bytes;
    *length -= bytes;
    return SECSuccess;
}

SECStatus
ssl3_ConsumeHandshakeNumber(PRUint32 *num, PRUint32 bytes,
                            PRUint8 **b, PRUint32 *length)
{
    PRUint64 num64;
    SECStatus rv;

    PORT_Assert(bytes <= sizeof(*num));
    if (bytes > sizeof(*num)) {
        fprintf(stderr, "ssl3_ConsumeHandshakeNumber: bytes larger than *num\n");
        return SECFailure;
    }
    rv = ssl3_ConsumeHandshakeNumber64(&num64, bytes, b, length);
    if (rv != SECSuccess) {
        return SECFailure;
    }
    *num = num64 & 0xffffffff;
    return SECSuccess;
}
/* Read in two values from the incoming decrypted byte stream "b", which is
 * *length bytes long.  The first value is a number whose size is "bytes"
 * bytes long.  The second value is a byte-string whose size is the value
 * of the first number received.  The latter byte-string, and its length,
 * is returned in the SECItem i.
 *
 * Returns SECFailure (-1) on failure.
 * On error, an alert has been sent, and a generic error code has been set.
 *
 * RADICAL CHANGE for NSS 3.11.  All callers of this function make copies
 * of the data returned in the SECItem *i, so making a copy of it here
 * is simply wasteful.  So, This function now just sets SECItem *i to
 * point to the values in the buffer **b.
 */
SECStatus
ssl3_ConsumeHandshakeVariable(SECItem *i, PRUint32 bytes,
                              PRUint8 **b, PRUint32 *length)
{
    PRUint32 count;
    SECStatus rv;

    PORT_Assert(bytes <= 3);
    i->len = 0;
    i->data = NULL;
    i->type = siBuffer;
    rv = ssl3_ConsumeHandshakeNumber(&count, bytes, b, length);
    if (rv != SECSuccess) {
        return SECFailure;
    }
    if (count > 0) {
        if (count > *length) {
            fprintf(stderr, "ssl3_ConsumeHandshakeVariable: count larger than *length\n");
            return SECFailure;
        }
        i->data = *b;
        i->len = count;
        *b += count;
        *length -= count;
    }
    return SECSuccess;
}

SECStatus parse_cookie_extension(PRCList * extensions, 
    TLSExtension * cookie, PRUint8 ** buffer, PRUint32 * length){
    // add the cookie extensino to extensions list
    PR_APPEND_LINK(&(cookie->link), extensions);
    cookie->type = ssl_tls13_cookie_xtn;
    // cookie length field consumes 2 bytes
    return ssl3_ConsumeHandshakeVariable(&(cookie->data), 2, buffer, length);
}

void print_cookie_ext(TLSExtension * ext){
    printf("type is %u %s\n", ext->type, get_ext_name(ext->type));
    printf("cookie length is %u\n", ext->data.len);
}

SECStatus parse_client_hello_supported_versions_extension(PRCList * extensions, 
    TLSExtension * supported_versions, PRUint8 ** buffer, PRUint32 * length){
    // add the extension to extensions list
    PR_APPEND_LINK(&(supported_versions->link), extensions);
    supported_versions->type = ssl_tls13_supported_versions_xtn;
    // client hello supported versions length field consumes 1 byte
    return ssl3_ConsumeHandshakeVariable(&(supported_versions->data), 1, buffer, length);
}

void print_client_hello_supported_versions_ext(TLSExtension * ext){
    printf("type is %u %s\n", ext->type, get_ext_name(ext->type));
    printf("length is %u\n", ext->data.len);
    printf("supported versions in client hello are: ");
    int i = 0;
    while(i < ext->data.len){
        uint16_t * ptr = (uint16_t *) &(ext->data.data[i]);
        uint16_t version = ntohs(*ptr);
        i += 2;
        printf("%u ", version);
    }
    printf("\n");
}

SECStatus parse_server_hello_supported_versions_extensions(PRCList * extensions, 
    TLSExtension * ext, PRUint8 ** buffer, PRUint32 * length){
        PR_APPEND_LINK(&(ext->link), extensions);
        ext->type = ssl_tls13_supported_versions_xtn;
        ext->data.len = 2;
        ext->data.data = *buffer;// no length field for supported extension in serverhello,
        // selected version consumes 2 bytes
        *buffer += 2;
        *length -= 2;
        return SECSuccess;
    }

void print_server_hello_supported_versions_ext(TLSExtension * ext){
    printf("type is: %u %s\n", ext->type, get_ext_name(ext->type));
    printf("length = %u\n", ext->data.len);
    printf("selected version = %u\n", ntohs(*((uint16_t *) ext->data.data)));
}

// each signature alrorithm enumerate consumes 2 bytes
SECStatus parse_signature_algorithm_cert_ext(PRCList * extensions, 
    TLSExtension * ext, PRUint8 ** buffer, PRUint32 * length){
    
    PR_APPEND_LINK(&(ext->link), extensions);
    ext->type = ssl_signature_algorithms_cert_xtn;
    // length field consumes 2 bytes
    return ssl3_ConsumeHandshakeVariable(&(ext->data), 2, buffer, length);
}

SECStatus parse_signature_algorithms_ext(PRCList * extensions,
    TLSExtension * ext, PRUint8 ** buffer, PRUint32 * length){
    
    PR_APPEND_LINK(&(ext->link), extensions);
    ext->type = ssl_signature_algorithms_xtn;
    // length field consumes 2 bytes
    return ssl3_ConsumeHandshakeVariable(&(ext->data), 2, buffer, length);
}

void print_signature_algorithms_ext(TLSExtension * ext){
    printf("type is %u %s\n", ext->type, get_ext_name(ext->type));
    // todo: print signature algorithms
}

void print_signature_algorithm_cert_ext(TLSExtension * ext){
    print_signature_algorithms_ext(ext);
}

// parse certificate authorities extension
SECStatus parse_certificate_authorities_ext(PRCList * extensions,
    TLSExtension * ext, PRUint8 ** buffer, PRUint32 * length){
        PR_APPEND_LINK(&(ext->link), extensions);
        ext->type = ssl_tls13_certificate_authorities_xtn;
        // length field consumes 2 bytes
        return ssl3_ConsumeHandshakeVariable(&(ext->data), 2, buffer, length);
}

void print_certificate_authorities_ext(TLSExtension * ext){
    printf("type is %u %s\n", ext->type, get_ext_name(ext->type));
    // todo: print the certificate authorities
}

// OID filters extension is sent only by server, in CertificateRequest message
// ignore post handshake client authentication extension for now


// parse supported groups extension 
SECStatus parse_supported_groups_ext(PRCList * extensions,
    TLSExtension * ext, PRUint8 ** buffer, PRUint32 * length){
        PR_APPEND_LINK(&(ext->link), extensions);
        ext->type = ssl_supported_groups_xtn;
        // length field consumes 2 bytes
        return ssl3_ConsumeHandshakeVariable(&(ext->data), 2, buffer, length);
}

void print_supported_groups_ext(TLSExtension * ext){
    printf("type is %u %s\n", ext->type, get_ext_name(ext->type));
    // todo: print groups' names
}

// parse key share extension in client hello
SECStatus parse_client_hello_key_share_ext(PRCList * extensions,
    TLSExtension * ext, PRUint8 ** buffer, PRUint32 * length){
        PR_APPEND_LINK(&(ext->link), extensions);
        ext->type = ssl_tls13_key_share_xtn;
        // length field consumes 2 bytes
        return ssl3_ConsumeHandshakeVariable(&(ext->data), 2, buffer, length);
}

struct key_share_entry_str{
    PRCList link;
    uint16_t group_name;
    SECItem data;
};

// get key share entries from key share extension in client hello
void get_key_share_entries(TLSExtension * ext, PRCList * key_share_entries){
    PRUint32 length = ext->data.len;
    uint8_t * buffer = ext->data.data;
    while(length > 0){
        struct key_share_entry_str * entry = (struct key_share_entry_str *) malloc(sizeof(struct key_share_entry_str));
        PR_APPEND_LINK(&(entry->link), key_share_entries);
        // read group name
        ssl3_ConsumeHandshakeNumber(&(entry->group_name), 2, &buffer, &length);
        // read key exchange
        ssl3_ConsumeHandshakeVariable(&(entry->data), 2, &buffer, &length);
    }
}

// parse key share extension in hello retry request message
SECStatus parse_hello_retry_request_key_share_ext(PRCList * extensions, 
    TLSExtension * ext, PRUint8 ** buffer, PRUint32 * length){
        PR_APPEND_LINK(&(ext->link), extensions);
        ext->type = ssl_tls13_key_share_xtn;
        ext->data.len = 2;
        ext->data.data = *buffer;
        *buffer += 2;
        *length -= 2;
        return SECSuccess;
}

void print_hello_retry_request_key_share_ext(TLSExtension * ext){
    pritnf("type is %u %s\n", ext->type, get_ext_name(ext->type));
    uint16_t * ptr = (uint16_t *) ext->data.data;
    uint16_t group_name = ntohs(*ptr);
    printf("group name is %u\n", group_name);
}

// parse key share extension in server hello message
// we make ext->data.data point to the key_share_entry_str struct
// ext->data.len is not used
SECStatus parse_server_hello_key_share_ext(PRCList * extensions,
    TLSExtension * ext, PRUint8 ** buffer, PRUint32 * length){
        PR_APPEND_LINK(&(ext->link), extensions);
        ext->type = ssl_tls13_key_share_xtn;

        struct key_share_entry_str * entry = (struct key_share_entries *) malloc(sizeof(struct key_share_entry_str));
        ext->data.data = (char *) entry;
        // now read group name
        ssl3_ConsumeHandshakeNumber(&(entry->group_name), 2, buffer, length);
        // now read key_exchange
        // for DH parameters, entry->data.data contains public value, big endian integer Y
        // for secp256r1, entry->data.data contains:
        // uint8 legacy_form = 4, opaque X[32] and opaque Y[32]
        // for secp384r1, entry->data.data contains:
        // uint8 legacy_form = 4, opaque X[48] and opaque Y[48]
        // for secp521r1, entry->data.data contains:
        // uint8 legacy_form = 4, opaque X[66] and opaque Y[66]
        // for x25519: entry->data.data contains the byte string inputs and outputs of
        // the corresponding functions defined in RFC7748, 32 bytes for x25519
        return ssl3_ConsumeHandshakeVariable(&(entry->data), 2, buffer, length);
}

// parse pre-shared key exchange modes extension
SECStatus parse_pre_shared_key_exchange_modes_ext(PRCList * extensions,
    TLSExtension * ext, PRUint8 ** buffer, PRUint32 * length){
        PR_APPEND_LINK(&(ext->link), extensions);
        ext->type = ssl_tls13_psk_key_exchange_modes_xtn;
        return ssl3_ConsumeHandshakeVariable(&(ext->data), 1, buffer, length);
}

char * get_psk_exhange_mode_name(uint8_t mode){
    if(mode == 0){
        return "psk_ke psk-only key establishment";
    } else if(mode == 1){
        return "psk_dhe_ke with (EC)DHE key establishment";
    } else {
        return "illegal psk exchange mode";
    }
}
void print_pre_shared_key_exchange_modes(TLSExtension * ext){
    printf("type is %u %s\n", ext->type, get_ext_name(ext->type));
    printf("%u modes: ", ext->data.len);
    int i;
    for(i = 0;i < ext->data.len;i++){
        uint8_t mode = (uint8_t) ext->data.data[i];
        pritnf("%u %s\n", mode, get_psk_exhange_mode_name(mode));
    }
}

// parse eary data 
// does not include type
// type is included in TLSExtension
// every protocol version consumes two bytes
struct client_hello_supported_versions_extension{
    uint16_t len; // length of data in bytes
    uint8_t * data;
};

struct server_hello_supported_version_extension{
    uint16_t selected_version;
};


struct client_hello_str{

    PRCList extensions;
};

TLSExtension * find_extension(PRCList * extensions_list, SSLExtensionType extension_type){
    PRCList * cursor;
    for(cursor = PR_NEXT_LINK(extensions_list); cursor != extensions_list; cursor = PR_NEXT_LINK(cursor)){
        TLSExtension * extension = (TLSExtension *) cursor;
        if(extension->type == extension_type){
            return extension;
        }
    }
}

// parse client hello and print it
// buffer starts from tcp payload data
void print_client_hello(unsigned char * buffer){
    int idx = 0;
    uint8_t record_type = buffer[0];
    idx++;
    uint16_t legacy_record_version = ntohs(*((uint16_t *) buffer + idx));
    idx += 2;
    uint16_t record_length = ntohs(*((uint16_t *) buffer + idx));
    idx += 2;

    uint8_t msg_type = (uint8_t) buffer[idx];
    idx += 1;
    uint16_t msg_length = ntohs(*((uint16_t *) buffer + idx));
    idx += 2;
    uint16_t legacy_version = ntohs(*((uint16_t *) buffer + idx));
    idx += 2;
    uint8_t * client_hello_random = (uint8_t *) buffer;
    idx += 32;
    
}

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
void asymmetric_handle_connection(int client_fd, int server_fd){
    fd_set read_fds;
    char buffer[2048];
    int len;

    printf("forward_data is called\n");
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 0;
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
                // read from one, send to another
                len = read(client_fd, buffer, 2048);
                if(len <= 0){
                    // close the sockets
                    close(client_fd);
                    close(server_fd);
                    return;
                } else {
                    printf("forward_data: read from one, send to another\n");
                    write(server_fd, buffer, len);
                }
            } else {
                //fprintf(stderr, "one is not set\n");
            }

            if(FD_ISSET(server_fd, &read_fds)){
                // read from another, send to one
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
                fprintf(stderr, "another is not set\n");
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