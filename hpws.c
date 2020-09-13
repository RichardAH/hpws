#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sha.h>

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
    int sock = create_socket(4433);
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

    // set up SSL
    SSL *ssl;
    SSL_CTX *ctx;
    init_openssl();
    ctx = create_context();
    configure_context(ctx);
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client);
    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        goto end;
    }
        
    #define SSL_BUFFER_LENGTH 4096
    char buf[SSL_BUFFER_LENGTH];

    // 16 mib, but should be made configurable later
    #define SHM_BUFFER_LENGTH 16777216 

    // read HTTP request 
    int bytes_read = SSL_read(ssl, buf, SSL_BUFFER_LENGTH - 1);
    if (bytes_read < 1 || bytes_read > SSL_BUFFER_LENGTH - 1)
        goto end;
    buf[bytes_read] = '\0';

    printf("%s\n", buf);
    static char to_find[] = "Sec-WebSocket-Key: ";
    static char magic_string[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    
    // isolate the Key
    char* found = strstr( buf, to_find );
    if (!found)
        goto end;
    char* lineend = strstr( found, "\r\n" );
    if (!lineend)
        goto end;

    *lineend = 0;
    found += sizeof(to_find) - 1;

    // now concatenate our magic string to the end if there is space
    if ( SSL_BUFFER_LENGTH - ( lineend - buf ) <= sizeof(magic_string) )
        goto end;
    strcpy( lineend, magic_string );
    
    // compute SHA1 of the magic string
    unsigned char hash [ SHA_DIGEST_LENGTH ];
    SHA1( found, ( lineend - found + sizeof(magic_string) - 1 ), hash );

    // encode as base64
    char base64[ BASE64_LEN(SHA_DIGEST_LENGTH) ]; 
    if (!base64_encode( hash, SHA_DIGEST_LENGTH,  base64, sizeof(base64)))
        goto end;

    // write a repsonse 
    int bytes_to_write = snprintf(buf, SSL_BUFFER_LENGTH, 
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: %s\r\n"
        "\r\n", base64);
    if (bytes_to_write < 1)
        goto end;
    SSL_write(ssl, buf, bytes_to_write);

    // execute frame proxy loop for this client until disconnect
    
    #define AT_LEAST( x, offset, bytes_read, wait_for_bytes )\
    {if (bytes_read - offset < (x)) {\
        wait_for_bytes = x + offset;\
        continue;\
    }}

    #define STORE_MASKING_KEY( masking_key_raw, buf, o, offset )\
    {\
        printf("storing new masking key\n");\
        for (int i = 0; i < 12; ++i)\
            masking_key_raw[i] = buf[offset + o + (i % 4)];\
    }

    #define SEND_CLOSE_FRAME( ssl, reason_code, reason_string )\
        {\
            if (!sent_close_frame) {\
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
                SSL_write(ssl, buf, (size_t)buf[1]);\
                sent_close_frame = reason_code;\
            }\
        }

    #define PROTOCOL_ERROR( ssl, msg )\
        {\
            SEND_CLOSE_FRAME( ssl, 1002, msg );\
            goto end;\
        }

    // todo: bitpack bool fields
    char state = 1;
    char fin = 0;
    short opcode = 0;
    int wait_for_bytes = 0;
    char masking_key_raw[12];
    uint64_t* masking_key = (uint64_t*)(masking_key_raw);
    uint64_t payload_bytes_processed = 0, payload_bytes_expected = 0;
    int sent_close_frame = 0, received_close_frame = 0, offset = 0, preliminary_size = 0, read_result = 0;

    for (bytes_read = 0;;)
    {
        
        if (bytes_read + 22 > SSL_BUFFER_LENGTH && state == 1 && offset > 0) {
            // we can't fit a full header in the remaining buffer
            // memcpy it back to start
            bytes_read -= offset;
            memcpy(buf, buf + offset, bytes_read);
            offset = 0;
        }

        if (( read_result = 
                SSL_read( ssl, buf + bytes_read, SSL_BUFFER_LENGTH - bytes_read - 8 )) <= 0)
            goto end;

        bytes_read += read_result;

        printf(
                "bytes_read: %d\n"
                "wait_for_bytes: %d\n"
                "state: %d\n"
                "offset: %d\n",

                bytes_read, wait_for_bytes, state, offset);
        
        if ( state < 3 && bytes_read < wait_for_bytes )
            continue;

        switch ( state )
        {
            case 1:       
            // read a header, will always have at least 2 bytes
            AT_LEAST(2, offset, bytes_read, wait_for_bytes);

            if (buf[offset + 0] & 0b01110000)
                PROTOCOL_ERROR(ssl, "rsv1-3 must be 0");

            // parse opcode            
            fin = buf[offset + 0] >> 7;
            opcode = buf[offset + 0] & 0b00001111; 
            if (!opcode && fin)
                PROTOCOL_ERROR(ssl, "fin bit set on opcode 0");
            
            // check mask flag is present
            if (buf[offset + 1] >> 7 == 0)
                PROTOCOL_ERROR(ssl, "masking flag nil");
 
            // parse size
            preliminary_size = buf[offset + 1] & 0b01111111;

            printf("opcode: %d\n", opcode);
            switch (opcode) {
                case 0: // continuation frame
                case 1: // text frame
                case 2: // binary frame
                    break;
                case 8: // close frame
                    {
                        AT_LEAST(preliminary_size, offset, bytes_read, wait_for_bytes);
                        received_close_frame = 1;
                        SEND_CLOSE_FRAME(ssl, 1000, "Bye!");
                        goto end;
                    }
                case 9: // ping frame
                case 10:  // pong frame, discard
                    {
                        // modify the opcode and send it back
                        AT_LEAST(preliminary_size, offset, bytes_read, wait_for_bytes);
                        if (opcode == 9) {        
                            buf[offset + 0]++; // its a pong!
                            if (!sent_close_frame)
                                SSL_write(ssl, buf + offset, preliminary_size);
                        }
                        offset += preliminary_size;
                        wait_for_bytes = 2;
                        bytes_read -= offset;
                        continue;
                    }
                default:
                    {
                        SEND_CLOSE_FRAME(ssl, 1002, "Invalid opcode");
                        goto end;
                    }
            }

            ++state;

            case 2:

            if (preliminary_size == 126) {
                AT_LEAST(8, offset, bytes_read, wait_for_bytes);
                payload_bytes_expected = 
                    ((uint64_t)buf[offset + 2] << 8) + ((uint64_t)buf[offset + 3] << 0);
                STORE_MASKING_KEY(masking_key_raw, buf, 4, offset);
                offset += 8;
            } else if (preliminary_size == 127) {
                AT_LEAST(14, offset, bytes_read, wait_for_bytes);
                payload_bytes_expected = 
                    ((uint64_t)buf[offset + 2] << 56) + ((uint64_t)buf[offset + 3] << 48) + 
                    ((uint64_t)buf[offset + 4] << 40) + ((uint64_t)buf[offset + 5] << 32) + 
                    ((uint64_t)buf[offset + 6] << 24) + ((uint64_t)buf[offset + 7] << 16) + 
                    ((uint64_t)buf[offset + 8] << 8) + ((uint64_t)buf[offset + 9] << 0); 
                STORE_MASKING_KEY(masking_key_raw, buf, 10, offset);
                offset += 14;
            } else {
                AT_LEAST(6, offset, bytes_read, wait_for_bytes);
                payload_bytes_expected = preliminary_size;
                STORE_MASKING_KEY(masking_key_raw, buf, 2, offset);
                offset += 6;
            }            
            ++state;

            case 3:;
                
                uint64_t read_cap = bytes_read;
                uint64_t payload_bytes_remaining = payload_bytes_expected - payload_bytes_processed;
                
                printf("bytes_remaining: %d\nbytes_expected: %d\nbytes_processed: %d\n", 
                    payload_bytes_remaining, payload_bytes_expected, payload_bytes_processed);                

                if (bytes_read >= payload_bytes_remaining + offset) {
                    read_cap = payload_bytes_remaining + offset;
                    state = 4;
                }          

                // this is an extremely tight loop, we dont want unnecessary condition checking in it
                for (uint64_t i = offset; i < read_cap ; i += 8)
                    *(uint64_t*)(buf + i) ^=
                        *((uint64_t*)(masking_key + (payload_bytes_processed  % 4)));
                
                // to keep the above loop tight we'll handle the edge case were we xor'd past the end
                for (uint64_t i = read_cap; i < read_cap + (read_cap % 8); ++i)
                    buf[i] ^= masking_key_raw[ (payload_bytes_processed + i) % 4 ];

                printf("packet: `%.*s`\n", (int)read_cap - offset, buf + offset);
    
                if (state == 4) 
                {
                    // we're up to the next frame
                    offset = read_cap;
                    state = 1;
                    payload_bytes_processed = 0;
                    continue;
                } 
                
                payload_bytes_processed += (read_cap - offset);
                offset = 0;
                bytes_read = 0;
                continue;

            default:
                SEND_CLOSE_FRAME(ssl, 1001, "Internal error");
                goto end;
        }
    }

    end:;
    printf("closing connection.\n");

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client);
    SSL_CTX_free(ctx);
    cleanup_openssl();

    return 0;
}
