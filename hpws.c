#define _GNU_SOURCE         /* See feature_test_macros(7) */
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
#include <sys/mman.h>
#include <getopt.h>

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



int create_listen(int port)
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

void configure_context(SSL_CTX *ctx, char* cert, char* key)
{
    SSL_CTX_set_ecdh_auto(ctx, 1);

    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
    }
}

int parse_int_or_exit(char* s, char* info) {
    int n;
    if (sscanf(s, "%d", &n) == 1)
        return n;

    if (info)
        fprintf(stderr, "failed to parse integer argument for %s: `%s`\n", info, s);
    else
        fprintf(stderr, "failed to parse integer argument: `%s`\n", s);
    
    exit(1000);
}

int main(int argc, char **argv)
{

    #define ABEND(code, str)\
    {\
        fprintf(stderr, "%s\n", str);\
        exit(code);\
    }

    // prepoulate defaults
    int ws_buffer_length = (16*1024*1024);
    int port = 443;
    char cert[256];
    strcpy(cert, "cert.pem");
    char key[256];
    strcpy(key, "key.pem");
    int control_fd = -1; 
    int max_con = 512;
    int max_con_ip = 5;
    char host[256]; // this is the host as parsed from the cmdline when in client mode
    host[0] = '\0';   
 
    int hpws_mode = 0;
    

    {
        int option_index = 0;
        optind = 1;
        //opterr = 0;
        static struct option long_options[] = {
            {"server", no_argument, 0,  1 },
            {"client", no_argument, 0,  1 },
            {"maxmsg", required_argument, 0,  1 },
            {"port", required_argument, 0,  1 },
            {"cert", required_argument, 0,  1 },
            {"key", required_argument, 0,  1 },
            {"cntlfd", required_argument, 0,  1 },
            {"maxcon", required_argument, 0,  1 },
            {"maxconip", required_argument, 0,  1 },
            
            {0, 0,  0,  0 }
        };
        while (getopt_long_only(argc, argv, "", long_options, &option_index) != -1)
        {
            //    printf("processing option: %d-%s\n", option_index, long_options[option_index].name);
            switch(option_index) {
                case 0:
                    hpws_mode |= 1;
                    continue;
                case 1:
                    hpws_mode |= 2;
                    continue;
                case 2:
                    ws_buffer_length = parse_int_or_exit(optarg, "maxmsg"); 
                    continue;
                case 3:
                    port = parse_int_or_exit(optarg, "port");
                    continue;
                case 4:
                    strcpy(cert, optarg);
                    continue;
                case 5:
                    strcpy(key, optarg);
                    continue;
                case 6:
                    control_fd = parse_int_or_exit(optarg, "cntlfd");
                    continue;
                case 7:
                    max_con = parse_int_or_exit(optarg, "maxcon");
                    continue;
                case 8:
                    max_con_ip = parse_int_or_exit(optarg, "maxconip");
                    continue;
                default:
                    continue;
            }
        }
    }

    printf("hpws mode: %d\n", hpws_mode);
    if (hpws_mode <= 0)
        ABEND(1, "must specify either --client or --server");

    if (hpws_mode >= 3)
        ABEND(2, "cannot specify both --client and --server, pick only one");
    
    // mode 1 == server
    // mode 2 == client

    

    if (hpws_mode == 2) {
        // client
            ABEND(1, "client mode not yet implemented sorry");
    }


    // todo options sanity checks 

    if (control_fd < 0)
        ABEND(5, "must supply a control FD --cntlfd <fd> as one side of a SOCK_SEQPACKET opened with socketpair");

    int is_server = ( hpws_mode == 1 );


    int client = -1;
    struct sockaddr_in6 client_addr;
    uint client_addr_len = sizeof(client_addr);

    if (is_server) {

        // RH todo: provide a way for listen loop (server) process to gracefully close and clean up fds
        int master_control_fd = control_fd; // control_fd will become client's fd every loop so make a note of original
    
        // listen in an accept loop
        int listen_sock = create_listen(9001);
        for(;;) {

            client = accept(listen_sock, (struct sockaddr*)&client_addr, &client_addr_len);
            if (client < 0) {
                perror("Unable to accept");
                exit(EXIT_FAILURE);
            }

            // RH TODO process/ connection / ip counting here

            // the instant we have done an accept we need to socketpair() and set up a new
            // control fd for the child we about to fork(). once we have the pair we send
            // one end to the child and one end down the master_control_fd
            // then the server closes all ends it owns
            int child_control_fd[2];
            if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, child_control_fd)) {
                //RH TODO should we kill off the proc here?
                fprintf(stderr, "failed to create socketpair for new accept, closing connection\n");
                close(client);
                continue;
            }
                
            // execution to here means we will service the client, send the socketpair fd
            {
                struct msghdr msg = { 0 };
                struct cmsghdr *cmsg;
                int send_fd[1] = {child_control_fd[1]} ;  /* Contains the file descriptors to pass */
                char iobuf[1];
                struct iovec io = {
                    .iov_base = iobuf,
                    .iov_len = sizeof(iobuf)
                };
                union {         /* Ancillary data buffer, wrapped in a union
                                   in order to ensure it is suitably aligned */
                    char buf[CMSG_SPACE(sizeof(send_fd))];
                    struct cmsghdr align;
                } u;

                msg.msg_iov = &io;
                msg.msg_iovlen = 1;
                msg.msg_control = u.buf;
                msg.msg_controllen = sizeof(u.buf);
                cmsg = CMSG_FIRSTHDR(&msg);
                cmsg->cmsg_level = SOL_SOCKET;
                cmsg->cmsg_type = SCM_RIGHTS;
                cmsg->cmsg_len = CMSG_LEN(sizeof(int));
                memcpy(CMSG_DATA(cmsg), send_fd,  sizeof(int));

                if (sendmsg(master_control_fd, &msg, 0) < 0)
                {
                    fprintf(stderr, "could not send control line fd for newly connected client down master control line");
                    close(client);
                    close(child_control_fd[0]);
                    close(child_control_fd[1]);
                    continue;
                }    
            }

            // todo: count clients / sub processes
            if (fork()) {
                close(child_control_fd[0]);
                close(child_control_fd[1]);
                close(client);
                continue;
            }
            
            // fall through to this point in code indicates this is a child process
            close(child_control_fd[1]);
            control_fd = child_control_fd[0];
            close(listen_sock);
            break;
        }
    } else {

        // RH TODO client = connect (....)
        fprintf(stderr, "client connect not implemented\n");
        exit(10);
    }

    // once we fall through to this point in execution the program is the same for
    // 1) a connected client that was just accept()ed
    // 2) a connected client that was just connect()ed
    // the control_fd messages are the same, the buffers are the same and the proxy is the same

    // first thing the new client always does is send its address to the control line
    if (send(control_fd, (void*)&client_addr, sizeof(client_addr), 0) != sizeof(client_addr))
        ABEND(6, "could not send client_addr to control fd");

    printf("connection established\n");

         
    char* ws_buffers[4];//ws_buffer_length];


    // rotating (swapping) buffers in and out
    // both processes have the following
    // 1. a buffer currently locked by the opposite process (being read)
    // 2. a buffer currently being written to by this process (being written)
    // 3. the buffer being written to will only be handed to the other process
    //    when the buffer being read from is handed back 
    //    this is so there is always a buffer to write into
    int ws_buffer_fd[] = {
        memfd_create("hpws_to_core_1", 0),
        memfd_create("hpws_to_core_2", 0),
        memfd_create("core_to_hpws_1", 0),
        memfd_create("core_to_hpws_2", 0)
    };
    
    for (int i = 0; i < 4; ++i) {
        if (ws_buffer_fd[i] < 0) {
            perror("failed to create memfd\n");
            close(client);
            return 1;
        }
        if (ftruncate(ws_buffer_fd[i], ws_buffer_length)) {
            perror("could not ftruncate memfd\n");
            close(client);
            return 1;
        }
        void* mapping = mmap(NULL, ws_buffer_length, PROT_WRITE | PROT_READ, MAP_SHARED, ws_buffer_fd[i], 0);
        if (mapping == (void*)-1) {
            perror("failed to mmap memfd\n");
            close(client);
            return 1;
        }
        ws_buffers[i] = mapping;
        printf("fd %d: %d - %x\n", i, ws_buffer_fd[i], mapping);   
    }

    // second thing the new client does is send its buffer fd's to the control line
    {
        struct msghdr msg = { 0 };
        struct cmsghdr *cmsg;
        char iobuf[1];
        struct iovec io = {
            .iov_base = iobuf,
            .iov_len = sizeof(iobuf)
        };
        union {         /* Ancillary data buffer, wrapped in a union
                           in order to ensure it is suitably aligned */
            char buf[CMSG_SPACE(sizeof(ws_buffer_fd))];
            struct cmsghdr align;
        } u;

        msg.msg_iov = &io;
        msg.msg_iovlen = 1;
        msg.msg_control = u.buf;
        msg.msg_controllen = sizeof(u.buf);
        cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(int) * 4);
        memcpy(CMSG_DATA(cmsg), ws_buffer_fd, 4 * sizeof(int));

        if (sendmsg(control_fd, &msg, 0) < 0)
            ABEND(7, "could not send buffer fds down control line");
    }


    //todo: - limit ssl_read to the size of the current ws frame to avoid reading in part of the  next frame
    //      - SCM_RIGHTS
    //      - buffer swapping
    //      - hpcore to hpws pipeline
    //      - client mode
    //      - child process limit
    //      - ip limit
    //      - cmd line specification of limits
    //      - configurable SHM size


    // set up SSL
    SSL *ssl;
    SSL_CTX *ctx;
    init_openssl();
    ctx = create_context();
    configure_context(ctx, cert, key);
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

 
    #define WS_AT_LEAST( x, offset, bytes_read, wait_for_bytes )\
    {if (bytes_read - offset < (x)) {\
        wait_for_bytes = x + offset;\
        break;\
    }}

    #define WS_STORE_MASKING_KEY( masking_key_raw, buf, o, offset )\
    {\
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

    #define WS_SEND_TEXT_FRAME( reason_string )\
        {\
            printf("sending test frame `%s`\n", reason_string);\
            unsigned char buf[127];\
            buf[0] = 0b10000001;\
            buf[1] =  sizeof(reason_string)-1 > 125 ? 125 : sizeof(reason_string)-1;\
            memcpy(buf + 2, reason_string, (size_t)buf[1]);\
            SSL_ENQUEUE(buf, (size_t)buf[1] + 2);\
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
        ws_upto = 0, ws_preliminary_size = 0, ws_read_result = 0;

    int ws_bytes_received = 0;

    char* ws_buf_decode = ws_buffers[0]; 
    char* ws_buf_encode = ws_buffers[2]; 

// \/ ----- END WS 

    for (;;) {

        fdset[0].events &= ~POLLOUT;
 
        if (ssl_write_len > 0)
            fdset[0].events |=  POLLOUT;
      
        int ready = poll(&fdset[0], 1 /* todo: change later */, -1);

        //printf("ready? %ld, sslwritelen %ld\n", ready, ssl_write_len);

        if (!ready)
            continue;

        
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
            //printf("outgoing data %ld\n", bytes_written);
            if (bytes_written <= 0)
                GOTO_ERROR("unable to write encrypted bytes to socket", ssl_error); 
            if (bytes_written < ssl_write_len)
                memmove(ssl_write_buf, ssl_write_buf + bytes_written, ssl_write_len - bytes_written);
            ssl_write_len -= bytes_written;
            ssl_write_buf = (char*)realloc(ssl_write_buf, ssl_write_len);
            continue;
        }

        // INCOMING DATA
        if (fdset[0].revents & POLLIN) {
            
            bytes_read = read(client, ssl_buf, sizeof(ssl_buf));
            /*fprintf(stderr, "raw bytes read %ld\nrawbytes:`", bytes_read);
            fwrite(ssl_buf, 1, bytes_read, stderr);
            fprintf(stderr, "`\n");*/
            if (bytes_read <= 0) 
                GOTO_ERROR("client closed connection", client_closed);

            bytes_written = BIO_write(rbio, ssl_buf, bytes_read);
            if (bytes_written <= 0)
                GOTO_ERROR("could not write raw bytes to openssl from incoming socket", ssl_error);
               
            if ( !SSL_is_init_finished(ssl) ) {
                int n = SSL_do_handshake(ssl);
                int e = SSL_get_error(ssl, n);
                SSL_FLUSH_OUT()
            } 

            if (SSL_is_init_finished(ssl)){

                for (;;) {
                    if ( ws_state == 0 ) {
                        // we do one single read when the ws hasn't protocol upgraded yet
                    
                        // todo: should we loop to ensure a complete http request?
                        int bytes_read = SSL_read( ssl, ws_buf_decode, ws_buffer_length - 1 );
                        fprintf(stderr, "--bytes read: %d\n", bytes_read); 
                        
                        if (bytes_read <= 0)
                            goto skip_ws;

                        ws_buf_decode[bytes_read-1] = '\0';


                    } else {

                        ws_read_result = 
                            SSL_read( ssl, ws_buf_decode + ws_bytes_received, ws_buffer_length - ws_bytes_received - 8 );

                        if (ws_read_result <= 0)
                            goto skip_ws;

                        ws_bytes_received += ws_read_result;

                        /*printf(
                                "bytes_read: %d\n"
                                "wait_for_bytes: %d\n"
                                "state: %d\n"
                                "offset: %d\n",

                                ws_bytes_received, ws_wait_for_bytes, ws_state, ws_upto);
                     */
                    }

                    //fprintf(stderr, "ws_state: %d\n", ws_state); 
                    if ( !( ws_state < 3 && ws_bytes_received < ws_wait_for_bytes) )
                    switch ( ws_state )
                    {

                        case 0:
                        {
                            static char to_find[] = "Sec-WebSocket-Key:";
                            static char magic_string[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
                            
                            // isolate the Key
                            char* found = strstr( ws_buf_decode, to_find );
                            if (!found)
                                GOTO_ERROR("websocket header not detected", ws_handshake_error);

                            char* lineend = strstr( found, "\r\n" );
                            if (!lineend)
                                GOTO_ERROR("websocket header not detected", ws_handshake_error);

                            *lineend = 0;
                            found += sizeof(to_find) - 1;

                            // clear any linear whitespace at the start of the field
                            for (; (*found == ' ' || *found == '\t') &&
                                    found < ws_buf_decode + ws_buffer_length; ++found);

                            // clear any linear whitespace at the end of the field
                            for (; (*lineend == ' ' || *lineend == '\t') &&
                                    lineend > found; --lineend);

                            // now concatenate our magic string to the end if there is space
                            if ( ws_buffer_length - ( lineend - ws_buf_decode ) <= sizeof(magic_string) )
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
                            int bytes_to_write = snprintf(ws_buf_decode, ws_buffer_length, 
                                "HTTP/1.1 101 Switching Protocols\r\n"
                                "Upgrade: websocket\r\n"
                                "Connection: Upgrade\r\n"
                                "Sec-WebSocket-Accept: %s\r\n"
                                "\r\n", base64);
                            if (bytes_to_write < 1)
                                GOTO_ERROR("could not create response message", ws_handshake_error);

                            SSL_ENQUEUE(ws_buf_decode, bytes_to_write);
                                                   
                            ++ws_state;
                            WS_SEND_TEXT_FRAME("hello world!\n");

                            break; 
                        }



                        case 1:       
                        // read a header, will always have at least 2 bytes
                        WS_AT_LEAST(2, ws_upto, ws_bytes_received, ws_wait_for_bytes);

                        if (ws_buf_decode[ws_upto + 0] & 0b01110000)
                            WS_PROTOCOL_ERROR("rsv1-3 must be 0");

        
                        // parse opcode            
                        ws_fin = ((ws_buf_decode[ws_upto + 0] >> 7) & 0x1);

                        ws_opcode = ws_buf_decode[ws_upto + 0] & 0b00001111; 
                        if (!ws_opcode && ws_fin)
                            WS_PROTOCOL_ERROR("fin bit set on opcode 0");
                        
                        // check mask flag is present
                        if (ws_buf_decode[ws_upto + 1] >> 7 == 0)
                            WS_PROTOCOL_ERROR("masking flag nil");
             
                        // parse size
                        ws_preliminary_size = ws_buf_decode[ws_upto + 1] & 0b01111111;

                        //printf("opcode: %d\n", ws_opcode);
                        switch (ws_opcode) {
                            case 0: // continuation frame
                            case 1: // text frame
                            case 2: // binary frame
                                break;
                            case 8: // close frame
                                {
                                    WS_AT_LEAST(ws_preliminary_size, ws_upto, ws_bytes_received, ws_wait_for_bytes);
                                    ws_received_close_frame = 1;
                                    WS_SEND_CLOSE_FRAME(1000, "Bye!");
                                    GOTO_ERROR("ws closing due to close frame", ws_graceful_close);
                                }
                            case 9: // ping frame
                            case 10:  // pong frame, discard
                                {
                                    // modify the opcode and send it back
                                    WS_AT_LEAST(ws_preliminary_size, ws_upto, ws_bytes_received, ws_wait_for_bytes);
                                    printf("ping/pong frame\n");
                                    if (ws_opcode == 9) {        
                                        ws_buf_decode[ws_upto + 0]++; // its a pong!
                                        if (!ws_sent_close_frame)
                                            SSL_ENQUEUE(ws_buf_decode + ws_upto, ws_preliminary_size);
                                    }
                                    ws_upto += ws_preliminary_size;
                                    ws_wait_for_bytes = 2;
                                    ws_bytes_received -= ws_upto;
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
                            WS_AT_LEAST(8, ws_upto, ws_bytes_received, ws_wait_for_bytes);
                            ws_payload_bytes_expected = 
                                ((uint64_t)ws_buf_decode[ws_upto + 2] << 8) + ((uint64_t)ws_buf_decode[ws_upto + 3] << 0);
                            WS_STORE_MASKING_KEY(ws_masking_key_raw, ws_buf_decode, 4, ws_upto);
                            ws_upto += 8;
                        } else if (ws_preliminary_size == 127) {
                            WS_AT_LEAST(14, ws_upto, ws_bytes_received, ws_wait_for_bytes);
                            ws_payload_bytes_expected = 
                                ((uint64_t)ws_buf_decode[ws_upto + 2] << 56) + ((uint64_t)ws_buf_decode[ws_upto + 3] << 48) + 
                                ((uint64_t)ws_buf_decode[ws_upto + 4] << 40) + ((uint64_t)ws_buf_decode[ws_upto + 5] << 32) + 
                                ((uint64_t)ws_buf_decode[ws_upto + 6] << 24) + ((uint64_t)ws_buf_decode[ws_upto + 7] << 16) + 
                                ((uint64_t)ws_buf_decode[ws_upto + 8] << 8) +  ((uint64_t)ws_buf_decode[ws_upto + 9] << 0); 
                            WS_STORE_MASKING_KEY(ws_masking_key_raw, ws_buf_decode, 10, ws_upto);
                            ws_upto += 14;
                        } else {
                            WS_AT_LEAST(6, ws_upto, ws_bytes_received, ws_wait_for_bytes);
                            ws_payload_bytes_expected = ws_preliminary_size;
                            WS_STORE_MASKING_KEY(ws_masking_key_raw, ws_buf_decode, 2, ws_upto);
                            ws_upto += 6;
                        }            
                        ++ws_state;

                        case 3:;
                            
                            uint64_t ws_next = ws_bytes_received;
                            uint64_t ws_payload_bytes_remaining =
                                ws_payload_bytes_expected - ws_payload_bytes_processed;
                            
                            //printf("bytes_remaining: %d\nbytes_expected: %d\nbytes_processed: %d\n", 
                            //    ws_payload_bytes_remaining, ws_payload_bytes_expected, ws_payload_bytes_processed);                

                            if (ws_bytes_received >= ws_payload_bytes_remaining + ws_upto) {
                                ws_next = ws_payload_bytes_remaining + ws_upto;
                                ws_state = 4;
                            }          
        
                            // this is an extremely tight loop, we dont want unnecessary condition checking in it
                            for (uint64_t i = ws_upto; i < ws_next ; i += 8)
                                *(uint64_t*)(ws_buf_decode + i) ^=
                                    *((uint64_t*)(ws_masking_key + (ws_payload_bytes_processed % 4)));
                            
                            // to keep the above loop tight we'll handle the edge case were we xor'd past the end
                            for (uint64_t i = ws_next; i < ws_next + (ws_next % 8); ++i) 
                                ws_buf_decode[i] ^= ws_masking_key_raw[ (ws_payload_bytes_processed + i) % 4 ];


                            static int line = 0;
                            printf("%05d: %02d/%02d - %d offset: %d packet: `%.*s`\n", line++, ws_payload_bytes_remaining, ws_payload_bytes_expected, ws_fin, ws_upto, (int)ws_next - ws_upto - ( *(ws_buf_decode + ws_upto + ws_next - ws_upto - 1) == '\n' ? 1 : 0 ),
                                ws_buf_decode + ws_upto);
                            
                
                            if (ws_state == 4 || ws_fin) 
                            {

                                // we're up to the next frame, copy back to start of buffer
                                if (ws_bytes_received - ws_upto > 0) {
                                    memcpy(ws_buf_decode, ws_buf_decode + ws_next, ws_bytes_received - ws_next);
                                }
                                ws_bytes_received -= ws_next;
                                ws_upto = 0;
                                ws_state = 1;
                                ws_payload_bytes_processed = 0;
                                ws_payload_bytes_remaining = 0;
                                break;
                            } 
                            
                            ws_payload_bytes_processed += (ws_next - ws_upto);
                            ws_upto = ws_next;
                            break;

                        default:
                            WS_SEND_CLOSE_FRAME(1001, "Internal error");
                            GOTO_ERROR("ws internal error", ws_protocol_error);
                    }
                    
                    SSL_FLUSH_OUT()
                }
            }
        }

        skip_ws:
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

    }

    ws_handshake_error:;
    ws_protocol_error:;
    ws_graceful_close:;
    socket_error:;
    ssl_error:;
    client_closed:;

    printf("finished %d\n", getpid());
    close(client);
    close(control_fd);
    for (int i = 0; i < 4; ++i)
        if (ws_buffer_fd[i] > -1)
            close(ws_buffer_fd[i]);

    SSL_free(ssl);
    free(ssl_write_buf);
    free(ssl_encrypt_buf);

    return 0;
}
