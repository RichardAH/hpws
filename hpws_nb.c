#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <poll.h>
#include <fcntl.h>

// base64 from http://web.mit.edu/freebsd/head/contrib/wpa/src/utils/base64.c
static const unsigned char base64_table[65] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

#define BASE64_LEN( x ) ( x * 4 / 3 + 5 )
unsigned char * base64_encode(
    unsigned char* src,
    size_t len,
    unsigned char* out,
	size_t out_len
){
	unsigned char  *pos;
	const unsigned char *end, *in;
	int line_len;

    if (out_len < len)
        return NULL;

	end = src + len;
	in = src;
	pos = out;
	while (end - in >= 3) {
		*pos++ = base64_table[in[0] >> 2];
		*pos++ = base64_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
		*pos++ = base64_table[((in[1] & 0x0f) << 2) | (in[2] >> 6)];
		*pos++ = base64_table[in[2] & 0x3f];
		in += 3;
	}

	if (end - in) {
		*pos++ = base64_table[in[0] >> 2];
		if (end - in == 1) {
			*pos++ = base64_table[(in[0] & 0x03) << 4];
			*pos++ = '=';
		} else {
			*pos++ = base64_table[((in[0] & 0x03) << 4) |
					      (in[1] >> 4)];
			*pos++ = base64_table[(in[1] & 0x0f) << 2];
		}
		*pos++ = '=';
	}

	*pos = '\0';
	return out;
}



int create_socket(int port)
{
    int s;
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
	perror("Unable to create socket");
	exit(EXIT_FAILURE);
    }

    int optval = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));

    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
	perror("Unable to bind");
	exit(EXIT_FAILURE);
    }

    if (listen(s, 1) < 0) {
	perror("Unable to listen");
	exit(EXIT_FAILURE);
    }

    return s;
}

void init_openssl()
{ 
    SSL_load_error_strings();	
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl()
{
    EVP_cleanup();
}

SSL_CTX *create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = SSLv23_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
	perror("Unable to create SSL context");
	ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_context(SSL_CTX *ctx)
{
    SSL_CTX_set_ecdh_auto(ctx, 1);

    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
    }
}

int main(int argc, char **argv)
{
    struct sockaddr_in addr;
    uint len = sizeof(addr);

    // listen in an accept loop
    int sock = create_socket(443);
    accept_loop:;
    int client = accept(sock, (struct sockaddr*)&addr, &len);
    if (client < 0) {
        perror("Unable to accept");
        exit(EXIT_FAILURE);
    }
    // todo: count clients / sub processes
    if (fork()) {
        close(client);
        goto accept_loop;
    }

    // fall through to this point in code indicates this is a child process
    close(sock);


    printf("accepted connection\n");

    // set up SSL
    SSL *ssl;
    SSL_CTX *ctx;
    init_openssl();
    ctx = create_context();
    configure_context(ctx);
    ssl = SSL_new(ctx);


    SSL_set_accept_state( ssl ); 
    BIO* rbio = BIO_new(BIO_s_mem()); /* SSL reads from, we write to. */
    BIO* wbio = BIO_new(BIO_s_mem()); /* SSL writes to, we read from. */
    SSL_set_bio(ssl, rbio, wbio);

    /* Bytes waiting to be written to socket. This is data that has been generated
    * by the SSL object, either due to encryption of user input, or, writes
    * requires due to peer-requested SSL renegotiation. */
    char* ssl_write_buf;
    size_t ssl_write_len;

    /* Bytes waiting to be encrypted by the SSL object. */
    char* ssl_encrypt_buf;
    size_t ssl_encrypt_len;

    struct pollfd fdset[2];
    memset(&fdset, 0, sizeof(fdset));

    fdset[0].fd = client;

    #define SSL_FAILED(x) (\
        (x) != SSL_ERROR_WANT_WRITE &&\
        (x) != SSL_ERROR_WANT_READ &&\
        (x) != SSL_ERROR_NONE )

    #define SSL_FLUSH_OUT()\
        {\
          ssize_t bytes_read = 0;\
          do {\
            bytes_read = BIO_read(wbio, ssl_buf, sizeof(ssl_buf));\
            printf("enque out %ld\n", bytes_read);\
            if (bytes_read > 0) {\
                ssl_write_buf = (char*)realloc(ssl_write_buf, ssl_write_len + bytes_read);\
                memcpy(ssl_write_buf + ssl_write_len, ssl_buf, bytes_read);\
                ssl_write_len += bytes_read;\
            }\
            else if (!BIO_should_retry(wbio))\
                GOTO_ERROR("ssl could not enqueue outward bytes", ssl_error);\
          } while (bytes_read > 0);\
        }

    #define GOTO_ERROR(x,y)\
        {fprintf(stderr, "error: %s\n", (x)); goto y;}

    #define SSL_BUFFER_LENGTH 4096
    #define WS_BUFFER_LENGTH 4096
    char ssl_buf[SSL_BUFFER_LENGTH]; //todo: zero copy?

    ssize_t bytes_read = 0, bytes_written = 0;
    int status = 0;
    fdset[0].events =  POLLERR | POLLHUP | POLLNVAL | POLLIN ;


    #define SSL_ENQUEUE(buf, len)\
        {\
            ssl_encrypt_buf = (char*)realloc(ssl_encrypt_buf, ssl_encrypt_len + len);\
            memcpy(ssl_encrypt_buf + ssl_encrypt_len, buf, len);\
            ssl_encrypt_len += len; \
        }

// ---- WS ----

    // 16 mib, but should be made configurable later
    #define SHM_BUFFER_LENGTH 16777216 
    
    char ws_buf[WS_BUFFER_LENGTH];
    
    #define WS_AT_LEAST( x, offset, bytes_read, wait_for_bytes )\
    {if (bytes_read - offset < (x)) {\
        wait_for_bytes = x + offset;\
        break;\
    }}

    #define WS_STORE_MASKING_KEY( masking_key_raw, buf, o, offset )\
    {\
        printf("storing new masking key\n");\
        for (int i = 0; i < 12; ++i)\
            masking_key_raw[i] = buf[offset + o + (i % 4)];\
    }

    #define WS_SEND_CLOSE_FRAME( reason_code, reason_string )\
        {\
            if (!ws_sent_close_frame) {\
                printf("sending close frame %d %s\n", reason_code, reason_string);\
                unsigned char buf[127];\
                buf[0] = 0b10001000;\
                buf[1] = (char)(reason_string ?\
                    ( sizeof(reason_string)-1 > 123 ? 123 : sizeof(reason_string)-1) : \
                    2);\
                buf[2] = ((reason_code) >> 8) & 0xff;\
                buf[3] = ((reason_code) >> 0) & 0xff;\
                if (buf[1] > 2)\
                    memcpy(buf + 4, reason_string, (size_t)buf[1]-2);\
                SSL_ENQUEUE(buf, (size_t)buf[1]);\
                ws_sent_close_frame = reason_code;\
            }\
        }

    #define WS_PROTOCOL_ERROR( msg )\
        {\
            WS_SEND_CLOSE_FRAME( 1002, msg );\
            GOTO_ERROR("ws protocol error", ws_protocol_error);\
        }

    // todo: bitpack bool fields
    char ws_state = 0;
    char ws_fin = 0;
    short ws_opcode = 0;
    int ws_wait_for_bytes = 0;
    char ws_masking_key_raw[12];
    uint64_t* ws_masking_key = (uint64_t*)(ws_masking_key_raw);
    uint64_t ws_payload_bytes_processed = 0, ws_payload_bytes_expected = 0;
    int ws_sent_close_frame = 0, ws_received_close_frame = 0,
        ws_offset = 0, ws_preliminary_size = 0, ws_read_result = 0;

    int ws_bytes_read = 0;

// \/ ----- END WS 

    for (;;) {

        fdset[0].events &= ~POLLOUT;
 
        if (ssl_write_len > 0)
            fdset[0].events |=  POLLOUT;
      
        int ready = poll(&fdset[0], 1 /* todo: change later */, -1);

        printf("ready? %ld, sslwritelen %ld\n", ready, ssl_write_len);

        if (!ready)
            continue;

        #define BYTE_TO_BINARY(byte)  \
          (byte & 0x80 ? '1' : '0'), \
          (byte & 0x40 ? '1' : '0'), \
          (byte & 0x20 ? '1' : '0'), \
          (byte & 0x10 ? '1' : '0'), \
          (byte & 0x08 ? '1' : '0'), \
          (byte & 0x04 ? '1' : '0'), \
          (byte & 0x02 ? '1' : '0'), \
          (byte & 0x01 ? '1' : '0') 

        printf("events was : %s %s %s\n", 
            ( fdset[0].revents & POLLERR ? "POLLERR" : "" ),
            ( fdset[0].revents & POLLHUP ? "POLLHUP" : "" ),
            ( fdset[0].revents & POLLNVAL ? "POLLNVAL" : "" )
        );
        printf("events: %c%c%c%c%c%c%c%c\n", BYTE_TO_BINARY(fdset[0].revents));
        
        if(fdset[0].revents & (POLLERR | POLLHUP | POLLNVAL) || read(client, ssl_buf, 0)) {

            int error = 0;
            socklen_t errlen = sizeof(error);
            getsockopt(client, SOL_SOCKET, SO_ERROR, (void *)&error, &errlen);
            printf("socket error: %d\n", error);
            
            GOTO_ERROR("err hup nval", client_closed);   
        }
        
        // OUTGOING DATA
        if (fdset[0].revents & POLLOUT && ssl_write_len) {
            bytes_written = write(client, ssl_write_buf, ssl_write_len);
            printf("outgoing data %ld\n", bytes_written);
            if (bytes_written <= 0)
                GOTO_ERROR("unable to write encrypted bytes to socket", ssl_error); 
            if (bytes_written < ssl_write_len)
                memmove(ssl_write_buf, ssl_write_buf + bytes_written, ssl_write_len - bytes_written);
            ssl_write_len -= bytes_written;
            ssl_write_buf = (char*)realloc(ssl_write_buf, ssl_write_len);
        }

        fprintf(stderr, "--a\n");
        // INCOMING DATA
        if (fdset[0].revents & POLLIN) {
            bytes_read = read(client, ssl_buf, sizeof(ssl_buf));
            fprintf(stderr, "raw bytes read %ld\n", bytes_read);
            if (bytes_read <= 0) 
                GOTO_ERROR("client closed connection", client_closed);

            bytes_written = BIO_write(rbio, ssl_buf, bytes_read);
            if (bytes_written <= 0)
                GOTO_ERROR("could not write raw bytes to openssl from incoming socket", ssl_error);
               
            if ( !SSL_is_init_finished(ssl) ) {
                int n = SSL_do_handshake(ssl);
                int e = SSL_get_error(ssl, n);
                if (e == SSL_ERROR_WANT_WRITE || e == SSL_ERROR_WANT_READ) 
                    SSL_FLUSH_OUT()
                else if (SSL_FAILED(e))
                    GOTO_ERROR("unable to complete handshake", ssl_error); 
            }

            if ( SSL_is_init_finished(ssl) ) {


                    if ( ws_state == 0 ) {
                        // we do one single read when the ws hasn't protocol upgraded yet
                    
                        // todo: should we loop to ensure a complete http request?
                        int bytes_read = SSL_read( ssl, ws_buf, WS_BUFFER_LENGTH - 1 );
                        
                        if (bytes_read <= 0)
                            GOTO_ERROR("no incoming http request for ws to process", ws_handshake_error);

                        ws_buf[bytes_read-1] = '\0';

                    } else {

                        if (ws_bytes_read + 22 > WS_BUFFER_LENGTH && ws_state == 1 && ws_offset > 0) {
                            // we can't fit a full header in the remaining buffer
                            // memcpy it back to start
                            ws_bytes_read -= ws_offset;
                            memcpy(ws_buf, ws_buf + ws_offset, ws_bytes_read);
                            ws_offset = 0;
                        }

                        ws_read_result = 
                            SSL_read( ssl, ws_buf + ws_bytes_read, WS_BUFFER_LENGTH - ws_bytes_read - 8 );

                        if (ws_read_result < 0)
                            GOTO_ERROR("couldnt read", client_closed);

                        if (ws_read_result == 0)
                            break;

                        ws_bytes_read += ws_read_result;

                        printf(
                                "bytes_read: %d\n"
                                "wait_for_bytes: %d\n"
                                "state: %d\n"
                                "offset: %d\n",

                                ws_bytes_read, ws_wait_for_bytes, ws_state, ws_offset);
                   
                    }
 
                    if ( !( ws_state < 3 && ws_bytes_read < ws_wait_for_bytes) )
                    switch ( ws_state )
                    {

                        case 0:
                        {
                            static char to_find[] = "Sec-WebSocket-Key:";
                            static char magic_string[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
                            
                            // isolate the Key
                            char* found = strstr( ws_buf, to_find );
                            if (!found)
                                GOTO_ERROR("websocket header not detected", ws_handshake_error);

                            char* lineend = strstr( found, "\r\n" );
                            if (!lineend)
                                GOTO_ERROR("websocket header not detected", ws_handshake_error);

                            *lineend = 0;
                            found += sizeof(to_find) - 1;

                            // clear any linear whitespace at the start of the field
                            for (; (*found == ' ' || *found == '\t') &&
                                    found < ws_buf + WS_BUFFER_LENGTH; ++found);

                            // clear any linear whitespace at the end of the field
                            for (; (*lineend == ' ' || *lineend == '\t') &&
                                    lineend > found; --lineend);

                            // now concatenate our magic string to the end if there is space
                            if ( WS_BUFFER_LENGTH - ( lineend - ws_buf ) <= sizeof(magic_string) )
                                GOTO_ERROR("unable to conat magic string during ws handshake", ws_handshake_error);

                            strcpy( lineend, magic_string );
                            
                            // compute SHA1 of the magic string
                            unsigned char hash [ SHA_DIGEST_LENGTH ];
                            SHA1( found, ( lineend - found + sizeof(magic_string) - 1 ), hash );

                            // encode as base64
                            char base64[ BASE64_LEN(SHA_DIGEST_LENGTH) ]; 
                            if (!base64_encode( hash, SHA_DIGEST_LENGTH,  base64, sizeof(base64)))
                                GOTO_ERROR("base64 encode failed", ws_handshake_error);

                            // write a repsonse 
                            int bytes_to_write = snprintf(ws_buf, WS_BUFFER_LENGTH, 
                                "HTTP/1.1 101 Switching Protocols\r\n"
                                "Upgrade: websocket\r\n"
                                "Connection: Upgrade\r\n"
                                "Sec-WebSocket-Accept: %s\r\n"
                                "\r\n", base64);
                            if (bytes_to_write < 1)
                                GOTO_ERROR("could not create response message", ws_handshake_error);

                            SSL_ENQUEUE(ws_buf, bytes_to_write);
                                                   
                            ++ws_state;
                            break; 
                        }



                        case 1:       
                        // read a header, will always have at least 2 bytes
                        WS_AT_LEAST(2, ws_offset, ws_bytes_read, ws_wait_for_bytes);

                        if (ws_buf[ws_offset + 0] & 0b01110000)
                            WS_PROTOCOL_ERROR("rsv1-3 must be 0");

                        // parse opcode            
                        ws_fin = ws_buf[ws_offset + 0] >> 7;
                        ws_opcode = ws_buf[ws_offset + 0] & 0b00001111; 
                        if (!ws_opcode && ws_fin)
                            WS_PROTOCOL_ERROR("fin bit set on opcode 0");
                        
                        // check mask flag is present
                        if (ws_buf[ws_offset + 1] >> 7 == 0)
                            WS_PROTOCOL_ERROR("masking flag nil");
             
                        // parse size
                        ws_preliminary_size = ws_buf[ws_offset + 1] & 0b01111111;

                        printf("opcode: %d\n", ws_opcode);
                        switch (ws_opcode) {
                            case 0: // continuation frame
                            case 1: // text frame
                            case 2: // binary frame
                                break;
                            case 8: // close frame
                                {
                                    WS_AT_LEAST(ws_preliminary_size, ws_offset, ws_bytes_read, ws_wait_for_bytes);
                                    ws_received_close_frame = 1;
                                    WS_SEND_CLOSE_FRAME(1000, "Bye!");
                                    GOTO_ERROR("ws closing due to close frame", ws_graceful_close);
                                }
                            case 9: // ping frame
                            case 10:  // pong frame, discard
                                {
                                    // modify the opcode and send it back
                                    WS_AT_LEAST(ws_preliminary_size, ws_offset, ws_bytes_read, ws_wait_for_bytes);
                                    if (ws_opcode == 9) {        
                                        ws_buf[ws_offset + 0]++; // its a pong!
                                        if (!ws_sent_close_frame)
                                            SSL_ENQUEUE(ws_buf + ws_offset, ws_preliminary_size);
                                    }
                                    ws_offset += ws_preliminary_size;
                                    ws_wait_for_bytes = 2;
                                    ws_bytes_read -= ws_offset;
                                    break;
                                }
                            default:
                                {
                                    WS_SEND_CLOSE_FRAME(1002, "Invalid opcode");
                                    GOTO_ERROR("ws invalid opcode", ws_protocol_error);
                                }
                        }

                        ++ws_state;

                        case 2:

                        if (ws_preliminary_size == 126) {
                            WS_AT_LEAST(8, ws_offset, ws_bytes_read, ws_wait_for_bytes);
                            ws_payload_bytes_expected = 
                                ((uint64_t)ws_buf[ws_offset + 2] << 8) + ((uint64_t)ws_buf[ws_offset + 3] << 0);
                            WS_STORE_MASKING_KEY(ws_masking_key_raw, ws_buf, 4, ws_offset);
                            ws_offset += 8;
                        } else if (ws_preliminary_size == 127) {
                            WS_AT_LEAST(14, ws_offset, ws_bytes_read, ws_wait_for_bytes);
                            ws_payload_bytes_expected = 
                                ((uint64_t)ws_buf[ws_offset + 2] << 56) + ((uint64_t)ws_buf[ws_offset + 3] << 48) + 
                                ((uint64_t)ws_buf[ws_offset + 4] << 40) + ((uint64_t)ws_buf[ws_offset + 5] << 32) + 
                                ((uint64_t)ws_buf[ws_offset + 6] << 24) + ((uint64_t)ws_buf[ws_offset + 7] << 16) + 
                                ((uint64_t)ws_buf[ws_offset + 8] << 8) +  ((uint64_t)ws_buf[ws_offset + 9] << 0); 
                            WS_STORE_MASKING_KEY(ws_masking_key_raw, ws_buf, 10, ws_offset);
                            ws_offset += 14;
                        } else {
                            WS_AT_LEAST(6, ws_offset, ws_bytes_read, ws_wait_for_bytes);
                            ws_payload_bytes_expected = ws_preliminary_size;
                            WS_STORE_MASKING_KEY(ws_masking_key_raw, ws_buf, 2, ws_offset);
                            ws_offset += 6;
                        }            
                        ++ws_state;

                        case 3:;
                            
                            uint64_t ws_read_cap = ws_bytes_read;
                            uint64_t ws_payload_bytes_remaining =
                                ws_payload_bytes_expected - ws_payload_bytes_processed;
                            
                            printf("bytes_remaining: %d\nbytes_expected: %d\nbytes_processed: %d\n", 
                                ws_payload_bytes_remaining, ws_payload_bytes_expected, ws_payload_bytes_processed);                

                            if (ws_bytes_read >= ws_payload_bytes_remaining + ws_offset) {
                                ws_read_cap = ws_payload_bytes_remaining + ws_offset;
                                ws_state = 4;
                            }          

                            // this is an extremely tight loop, we dont want unnecessary condition checking in it
                            for (uint64_t i = ws_offset; i < ws_read_cap ; i += 8)
                                *(uint64_t*)(ws_buf + i) ^=
                                    *((uint64_t*)(ws_masking_key + (ws_payload_bytes_processed  % 4)));
                            
                            // to keep the above loop tight we'll handle the edge case were we xor'd past the end
                            for (uint64_t i = ws_read_cap; i < ws_read_cap + (ws_read_cap % 8); ++i)
                                ws_buf[i] ^= ws_masking_key_raw[ (ws_payload_bytes_processed + i) % 4 ];

                            printf("packet: `%.*s`\n", (int)ws_read_cap - ws_offset, ws_buf + ws_offset);
                
                            if (ws_state == 4) 
                            {
                                // we're up to the next frame
                                ws_offset = ws_read_cap;
                                ws_state = 1;
                                ws_payload_bytes_processed = 0;
                                break;
                            } 
                            
                            ws_payload_bytes_processed += (ws_read_cap - ws_offset);
                            ws_offset = 0;
                            ws_bytes_read = 0;
                            break;

                        default:
                            WS_SEND_CLOSE_FRAME(1001, "Internal error");
                            GOTO_ERROR("ws internal error", ws_protocol_error);
                    }
                    

                status = SSL_get_error(ssl, bytes_read);

                if (status == SSL_ERROR_WANT_WRITE) 
                    SSL_FLUSH_OUT()
                else if (SSL_FAILED(status))
                    GOTO_ERROR("unable to complete incoming read", ssl_error); 

            }
        }

        // encrypt pending ssl queue
        if (!SSL_is_init_finished(ssl))
            continue;
        
        while (ssl_encrypt_len > 0) {
            int bytes_written = SSL_write(ssl, ssl_encrypt_buf, ssl_encrypt_len);

            if (bytes_written > 0) {
                /* consume the waiting bytes that have been used by SSL */
                if ((size_t)bytes_written < ssl_encrypt_len)
                    memmove(ssl_encrypt_buf, ssl_encrypt_buf+bytes_written, ssl_encrypt_len-bytes_written);
                ssl_encrypt_len -= bytes_written;
                ssl_encrypt_buf = (char*)realloc(ssl_encrypt_buf, ssl_encrypt_len);
                SSL_FLUSH_OUT();
            }


            status = SSL_get_error(ssl, bytes_written);

            if (status == SSL_ERROR_WANT_WRITE)
                SSL_FLUSH_OUT()
            else if (SSL_FAILED(status))
                GOTO_ERROR("unable to complete out going write", ssl_error);

            if (bytes_written == 0)
              break;
        }

        fprintf(stderr, "--c\n");
        
    }

    ws_handshake_error:;
    ws_protocol_error:;
    ws_graceful_close:;
    socket_error:;
    ssl_error:;
    client_closed:;

    printf("finished\n");
    close(client);
    SSL_free(ssl);
    free(ssl_write_buf);
    free(ssl_encrypt_buf);

    return 0;
}
