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
        goto handshake_error;
    }
        
    // read HTTP request 
    #define BUFFER_LENGTH 4096
    char buf[BUFFER_LENGTH];

    int bytes_read = SSL_read(ssl, buf, BUFFER_LENGTH - 1);
    if (bytes_read < 1 || bytes_read > BUFFER_LENGTH - 1)
        goto handshake_error;
    buf[bytes_read] = '\0';

    
    static char to_find[] = "Sec-WebSocket-Key: ";
    static char magic_string[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    
    // isolate the Key
    char* found = strstr( buf, to_find );
    if (!found)
        goto handshake_error;
    char* lineend = strstr( found, "\r\n" );
    if (!lineend)
        goto handshake_error;

    *lineend = 0;
    found += sizeof(to_find) - 1;

    // now concatenate our magic string to the end if there is space
    if ( BUFFER_LENGTH - ( lineend - buf ) <= sizeof(magic_string) )
        goto handshake_error;
    strcpy( lineend, magic_string );
    
    // compute SHA1 of the magic string
    unsigned char hash [ SHA_DIGEST_LENGTH ];
    SHA1( found, ( lineend - found + sizeof(magic_string) - 1 ), hash );

    // encode as base64
    char base64[ BASE64_LEN(SHA_DIGEST_LENGTH) ]; 
    if (!base64_encode( hash, SHA_DIGEST_LENGTH,  base64, sizeof(base64)))
        goto handshake_error;

    // write a repsonse 
    int bytes_to_write = snprintf(buf, BUFFER_LENGTH, 
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: %s\r\n"
        "\r\n", base64);
    if (bytes_to_write < 1)
        goto handshake_error;
    SSL_write(ssl, buf, bytes_to_write);

    // execute frame proxy loop for this client until disconnect
    //char buf_out[BUFFER_LENGTH];
    
    
    char fin = 0;
    short opcode = 0;

    unsigned long masking_key = 0;

    int wait_for_bytes = 0;
    #define AT_LEAST(x)\
    {if (bytes_read < (x)) {\
        wait_for_bytes = x;\
        continue;\
    }}

    char in_header = 1;
    uint64_t payload_bytes_remaining = 0;
    uint32_t masking_key = 0;


    while ( (bytes_read += SSL_read(ssl, buf + bytes_read, BUFFER_LENGTH - bytes_read)) > 0 ) 
    {
        if ( bytes_read < wait_for_bytes )
            continue;

        int offset = 0;
        if ( in_header )
        {
            // we can't start parsing a header until we have the first two bytes
            AT_LEAST(2);
            
            // read a header, will always have at least 2 bytes
            fin = buf[0] >> 7;
            if (buf[0] & 0b01110000)
                goto handshake_error;

            // parse opcode            
            opcode = buf[0] & 0b00001111; 
       

            // check mask flag is present
            if (buf[1] >> 7 == 0)
                goto handshake_error; 
 
            // parse size
            int preliminary_size = buf[1] & 0b01111111;

            if (preliminary_size == 126) {
                AT_LEAST(8);
                payload_bytes_remaining = 
                    (buf[2] << 8) + 
                    (buf[3] << 0);
                masking_key = 
                    (buf[4] << 24) +
                    (buf[5] << 16) +
                    (buf[6] << 8) +
                    (buf[7] << 0);
                    offset = 8;
            } else if (preliminary_size == 127) {
                AT_LEAST(14);
                payload_bytes_remaining = 
                    (buf[2] << 56) + 
                    (buf[3] << 48) + 
                    (buf[4] << 40) + 
                    (buf[5] << 32) + 
                    (buf[6] << 24) + 
                    (buf[7] << 16) + 
                    (buf[8] << 8) + 
                    (buf[9] << 0); 
                masking_key = 
                    (buf[10] << 24) +
                    (buf[11] << 16) +
                    (buf[12] << 8) +
                    (buf[13] << 0);
                    offset = 14;
            } else {
                AT_LEAST(6);
                masking_key = 
                    (buf[2] << 24) +
                    (buf[3] << 16) +
                    (buf[4] << 8) +
                    (buf[5] << 0);
                    offset = 6;
            }
            in_header = 0;
        }

        // execution beyond here is payload
        

    }

    goto end;

    handshake_error:
    printf("handshake error\n");

    end:

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client);
    SSL_CTX_free(ctx);
    cleanup_openssl();

    return 0;
}
