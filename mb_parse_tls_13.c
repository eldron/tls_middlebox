#include "mb_parse_tls_13.h"

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

void print_extensions(PRCList * ext_list){
    PRCList * cursor;
    for(cursor = PR_NEXT_LINK(ext_list); cursor != ext_list; cursor = PR_NEXT_LINK(cursor)){
        TLSExtension * ext = (TLSExtension *) cursor;
        printf("type is %u %s, length is %u\n", ext->type, get_ext_name(ext->type), ext->data.len);
    }
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

TLSExtension * find_extension(PRCList * extensions_list, SSLExtensionType extension_type){
    PRCList * cursor;
    for(cursor = PR_NEXT_LINK(extensions_list); cursor != extensions_list; cursor = PR_NEXT_LINK(cursor)){
        TLSExtension * extension = (TLSExtension *) cursor;
        if(extension->type == extension_type){
            return extension;
        }
    }
}

// parse server hello
// *buffer should point to legacy_version
// the HelloRetryRequest message uses the same struct reu as the ServerHello, but with random
// set to the special value of the SHA-256 of "HelloRetryRequest"
// upon receiving a message with type server_hello, client needs to examine the random value
// and see if it matches this value
SECStatus parse_server_hello(struct server_hello_str * server_hello,
    PRUint8 ** buffer, PRUint32 * length){
        uint32_t legacy_version;
        SECStatus rv;
        rv = ssl3_ConsumeHandshakeNumber(&legacy_version, 2, buffer, length);// legacy_version consumes 2 bytes
        if(rv == SECFailure){
            fprintf(stderr, "parse_server_hello: error reading legacy_version");
            return rv;
        }
        server_hello->legacy_version = (uint16_t) legacy_version;

        server_hello->random = *buffer;// random consumes 32 bytes
        *buffer += 32;
        *length -= 32;

        // legacy_session_id length consumes 1 byte
        rv = ssl3_ConsumeHandshakeVariable(&(server_hello->legacy_session_id), 1, buffer, length);
        if(rv == SECFailure){
            fprintf(stderr, "parse_server_hello: error reading legacy_session_id\n");
            return rv;
        }

        uint32_t cipher_suit;
        // cipher_suit consumes 2 bytes
        rv = ssl3_ConsumeHandshakeNumber(&cipher_suit, 2, buffer, length);
        if(rv == SECFailure){
            fprintf(stderr, "parse_server_hello: error reading cipher_suit\n");
            return rv;
        }
        server_hello->cipher_suit = (uint16_t) cipher_suit;

        uint32_t legacy_compression_method;
        // legacy_compression_method consumes 1 byte
        rv = ssl3_ConsumeHandshakeNumber(&legacy_compression_method, 1, buffer, length);
        if(rv == SECFailure){
            fprintf(stderr, "parse_server_hello: error reading legacy_compression_method\n");
            return rv;
        }
        server_hello->legacy_compression_method = (uint8_t) legacy_compression_method;

        // extensions length consumes 2 bytes
        rv = ssl3_ConsumeHandshakeVariable(&(server_hello->extensions), 2, buffer, length);
        if(rv == SECFailure){
            fprintf(stderr, "parse_server_hello: error reading extensions\n");
            return rv;
        }
        // parse extensions, link them together
        PR_INIT_CLIST(&(server_hello->ext_list));
        PRUint8 * buf = server_hello->extensions.data;
        PRUint32 len = server_hello->extensions.len;
        while(len > 0){
            TLSExtension * ext = (TLSExtension *) malloc(sizeof(TLSExtension));
            uint32_t type;
            rv = ssl3_ConsumeHandshakeNumber(&type, 2, &buf, &len);// extension type consumes 2 bytes
            if(rv == SECFailure){
                fprintf(stderr, "parse_server_hello: error reading extension type\n");
                return rv;
            }
            ext->type = (PRUint16) type;
            rv = ssl3_ConsumeHandshakeVariable(&(ext->data), 2, &buf, &len);
            if(rv == SECFailure){
                fprintf(stderr, "parse_server_hello: error reading extension content\n");
                return rv;
            }
            PR_APPEND_LINK(&(ext->link), &(server_hello->ext_list));
        }

        return SECSuccess;
}
// parse client hello
// *buffer should point to legacy_version
SECStatus parse_client_hello(struct client_hello_str * client_hello,
    PRUint8 ** buffer, PRUint32 * length){
        uint32_t legacy_version;
        ssl3_ConsumeHandshakeNumber(&legacy_version, 2, buffer, length);// legacy version consumes 2 bytes
        client_hello->legacy_version = (uint16_t) legacy_version;
        client_hello->random = *buffer;// random consumes 32 bytes
        *buffer += 32;
        *length -= 32;
        SECStatus rv;
        rv = ssl3_ConsumeHandshakeVariable(&(client_hello->legacy_session_id), 1, buffer, length);
        if(rv == SECFailure){
            fprintf(stderr, "parse_client_hello: error reading legacy_session_id\n");
            return rv;
        }
        rv = ssl3_ConsumeHandshakeVariable(&(client_hello->cipher_suits), 2, buffer, length);
        if(rv == SECFailure){
            fprintf(stderr, "parse_client_hello: error reading cipher_suits\n");
            return rv;
        }
        rv = ssl3_ConsumeHandshakeVariable(&(client_hello->legacy_compression_methods), 1, buffer, length);
        if(rv == SECFailure){
            fprintf(stderr, "parse_client_hello: error reading legacy_compression_methods\n");
            return rv;
        }
        rv = ssl3_ConsumeHandshakeVariable(&(client_hello->extensions), 2, buffer, length);
        if(rv == SECFailure){
            fprintf(stderr, "parse_client_hello: error reading extensions\n");
            return rv;
        }
        // parse extensions, link them together
        PR_INIT_CLIST(&(client_hello->ext_list));
        PRUint8 * buf = client_hello->extensions.data;
        PRUint32 len = client_hello->extensions.len;
        while(len > 0){
            TLSExtension * ext = (TLSExtension *) malloc(sizeof(TLSExtension));
            uint32_t type;
            rv = ssl3_ConsumeHandshakeNumber(&type, 2, &buf, &len);// extension type consumes 2 bytes
            if(rv == SECFailure){
                fprintf(stderr, "parse_client_hello: error reading extension type\n");
                return rv;
            }
            ext->type = (PRUint16) type;
            rv = ssl3_ConsumeHandshakeVariable(&(ext->data), 2, &buf, &len);
            if(rv == SECFailure){
                fprintf(stderr, "parse_client_hello: error reading extension content\n");
                return rv;
            }
            PR_APPEND_LINK(&(ext->link), &(client_hello->ext_list));
        }

        return SECSuccess;
}

SECStatus parse_record(PRUint8 ** buffer, PRUint32 len, uint8_t * content_type, 
    uint32_t * handshake_type, void * content_struct){
        SECStatus rv;
        *content_type = (*buffer)[0];// content type consumes 1 byte
        *buffer += 3;// legacy record version consumes 2 bytes
        uint16_t * ptr = (uint16_t *) (*buffer);
        uint16_t length = ntohs(*ptr);
        *buffer += 2;// length field consumes 2 bytes
        if(length > (len - 5)){
            fprintf(stderr, "parse_record error, length larger than (len - 5)\n");
            return SECFailure;
        } else {
            if(*content_type == content_handshake){
                PRUint32 msg_type;
                PRUint32 handshake_length;
                ssl3_ConsumeHandshakeNumber(&msg_type, 1, buffer, &length);// handshake type consumes 1 byte
                ssl3_ConsumeHandshakeNumber(&handshake_length, 3, buffer, &length);// handshake length consumes 3 bytes
                if(msg_type == ssl_hs_client_hello){
                    // parse client hello
                    *handshake_type = msg_type;
                    struct client_hello_str * client_hello = (struct client_hello_str *) malloc(sizeof(client_hello_str));
                    rv = parse_client_hello(client_hello, buffer, &handshake_length);
                    if(rv == SECFailure){
                        fprintf(stderr, "parse_record: error parse_client_hello\n");
                    }
                    return rv;
                } else if (msg_type == ssl_hs_server_hello){
                    // parse server hello
                    *handshake_type = msg_type;
                    struct server_hello_str * server_hello = (struct server_hello_str *) malloc(sizeof(server_hello_str));
                    rv = parse_server_hello(server_hello, buffer, &handshake_length);
                    if(rv == SECFailure){
                        fprintf(stderr, "parse_record: error parse_server_hello\n");
                    }
                    return rv;
                } else {
                    fprintf(stderr, "parse_record: unimplemented handshake type\n");
                    return SECSuccess;
                }
            } else {
                fprintf(stderr, "parse_record: unimplemented content type\n");
                return SECFailure;
            }
        }
}