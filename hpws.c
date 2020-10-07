/*
    HPWS - a TLS websocket server and client for hotpocket
    Author: Richard Holland
    Date: 7 October 2020

    Note to the reader:
    -------------------
    The code below is designed to be a minimal dependency all-in-one communication component for hotpocket, isolating 
    each connection and all of its state into one connection per process. The design is deliberately low level and due 
    to the lack of co-routines in C the entire component is programmed as a single event loop using macros to 
    manipulate stack-bound state and program flow. An attempt has been made to make it reasonably readable, however if
    you are unfamiliar with purely procedural code you might become somewhat lost.

    High-level overview:
    -------------------
    1.  A hotpocket (HP) instance requires to either connect out or allow others to connect in over tls websocket.
    2.  HP fork-execs HPWS with the appropriate command line options for the desired activity.
    3.  A control line (anonymous unix domain socket) is used to communicate control message between HPWS and HP.
    4.  HPWS forks for each incoming client (in server mode) or connects out directly (client mode).
    5.  Each time a new connection is established HPWS calls memfd_create to create anonymous buffers for sharing 
        incoming and outgoing data for that connection between HPWS and HP.
    6.  HPWS shares handles to these anonymous buffers over the control line (via SCM_RIGHTS).
    7.  When data becomes available in a buffer (for a connection) a control message is sent allowing the other party 
        to read or discard the message as needed.

*/

/*
** --------------------------------------------------------------------------------------------------------------------
**  Config
** --------------------------------------------------------------------------------------------------------------------
*/
#define DEBUG 1
#define SSL_BUFFER_LENGTH 4096
#define _GNU_SOURCE

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
#include <sys/types.h>
#include <netdb.h>

/*
** --------------------------------------------------------------------------------------------------------------------
**  Universal macros and prototypes
** --------------------------------------------------------------------------------------------------------------------
*/
#define GOTO_ERROR(x,y) { fprintf(stderr, "error: %s\n", (x)); goto y; }
#define ABEND(code, str) { fprintf(stderr, "%s\n", str); exit(code); }

#define BASE64_LEN( x ) ( x * 4 / 3 + 5 )
unsigned char * base64_encode( unsigned char* src, size_t len, unsigned char* out, size_t out_len );
void block_xor(unsigned char* buf, uint64_t start, uint64_t end, unsigned char* masking_key_x3);

int main(int argc, char **argv)
{

/*
** --------------------------------------------------------------------------------------------------------------------
**  Set up state variables
** --------------------------------------------------------------------------------------------------------------------
*/

    // ssl variables
    SSL* ssl = NULL;
    SSL_CTX* ctx = NULL;
    char* ssl_write_buf = NULL, *ssl_encrypt_buf = NULL;
    size_t ssl_write_len = NULL, ssl_encrypt_len = NULL;
    char cert[256]; strcpy(cert, "cert.pem");
    char key[256]; strcpy(key, "key.pem");
    char ssl_buf[SSL_BUFFER_LENGTH];
    ssize_t bytes_read = 0, bytes_written = 0;
    BIO* rbio = NULL;
    BIO* wbio = NULL;
    int status = 0;

    // socket variables
    union {
        struct sockaddr sa;
        struct sockaddr_in sin;
        struct sockaddr_in6 sin6;
        struct sockaddr_storage ss;
    } client_addr;
    size_t client_addr_len = sizeof(client_addr); memset(&client_addr, 0, client_addr_len);
    int client_fd = -1, control_fd = -1, port = 443, max_con = 512, max_con_ip = 5, is_server = 1, is_ipv6 = 0;
    int urand_fd = -1;
    char ip[40]; ip[0] = '\0';
    char host[256]; host[0] = '\0';             // this is the host as parsed from the cmdline when in client mode
    char get[256]; get[0] = '/'; get[1] = '\0'; // this is the uri to request in the upgrade message when connecting

    // websocket variables are prefixed with ws_
    unsigned char ws_masking_key[12];
    uint64_t ws_payload_bytes_expected = 0;
    uint64_t ws_payload_bytes_remaining = 0;
    uint64_t ws_payload_next = 0;
    int ws_buffer_length = (16*1024*1024);
    int ws_state = 0, ws_fin = 0, ws_opcode = 0, ws_wait_for_bytes = 0,
        ws_sent_close_frame = 0, ws_received_close_frame = 0,
        ws_payload_upto = 0, ws_preliminary_size = 0, ws_read_result = 0,
        ws_back_read = 0, ws_header_back_read = 0, ws_pending_read = 0, 
        ws_multi_frame_total_bytes_received = 0;
    unsigned char ws_buf_header[14];
    char* ws_buffer[4];
    int ws_buffer_fd[4] = {-1, -1, -1, -1};
    int ws_buffer_lock[] = {0, 0}; // 0 is ws_buffer[0], 1, is ws_buffer[1]
    char* ws_buf_decode = NULL; 

    // event loop variables
    struct pollfd fdset[2];
    memset(&fdset, 0, sizeof(fdset));

/*
** --------------------------------------------------------------------------------------------------------------------
**  Parse commandline arguments
** --------------------------------------------------------------------------------------------------------------------
*/
   { 
        #define PARSE_INT_OR_EXIT(str, msg, into_int)\
        {\
            if (sscanf(str, "%d", &into_int) != 1)\
                ABEND(10000, "failed to parse integer argument for " msg);\
        }

        int hpws_mode = 0; 
        int option_index = 0;
        optind = 1;

        static struct option long_options[] = {
            {"server",      no_argument,        0,      1 },
            {"client",      no_argument,        0,      1 },
            {"maxmsg",      required_argument,  0,      1 },
            {"port",        required_argument,  0,      1 },
            {"cert",        required_argument,  0,      1 },
            {"key",         required_argument,  0,      1 },
            {"cntlfd",      required_argument,  0,      1 },
            {"maxcon",      required_argument,  0,      1 },
            {"maxconip",    required_argument,  0,      1 },
            {"host",        required_argument,  0,      1 },
            {"ipv6",        no_argument,        0,      1 },
            {"get",         required_argument,  0,      1 },
            {0,             0,                  0,      0 }
        };

        while (getopt_long_only(argc, argv, "", long_options, &option_index) != -1)
        {
            if (DEBUG)
                printf("processing option: %d-%s\n", option_index, long_options[option_index].name);
            switch(option_index) {
                case 0:
                    hpws_mode |= 1;
                    continue;
                case 1:
                    hpws_mode |= 2;
                    continue;
                case 2:
                    PARSE_INT_OR_EXIT(optarg, "maxmsg", ws_buffer_length); 
                    continue;
                case 3:
                    PARSE_INT_OR_EXIT(optarg, "port", port);
                    continue;
                case 4:
                    strncpy(cert, optarg, sizeof(cert));
                    continue;
                case 5:
                    strncpy(key, optarg, sizeof(key));
                    continue;
                case 6:
                    PARSE_INT_OR_EXIT(optarg, "cntlfd", control_fd);
                    continue;
                case 7:
                    PARSE_INT_OR_EXIT(optarg, "maxcon", max_con);
                    continue;
                case 8:
                    PARSE_INT_OR_EXIT(optarg, "maxconip", max_con_ip);
                    continue;
                case 9:
                    strncpy(host, optarg, sizeof(host));
                    continue;
                case 10:
                    is_ipv6 = 1;
                    continue;
                case 11:
                    strncpy(get, optarg, sizeof(get));
                    continue;
                default:
                    continue;
            }
        }

        if (DEBUG)
            printf("hpws mode: %d\n", hpws_mode);
        
        if (hpws_mode <= 0)
            ABEND(1, "must specify either --client or --server");

        if (hpws_mode >= 3)
            ABEND(2, "cannot specify both --client and --server, pick only one");
     
        is_server = ( hpws_mode == 1 );

        if (!is_server && host[0] == '\0')
            ABEND(3, "must specify --host when invoking as a --client");
        
        if (control_fd < 0)
            ABEND(5, "must supply a control FD --cntlfd <fd> as one side of a SOCK_SEQPACKET opened with socketpair");
    }
/*
** --------------------------------------------------------------------------------------------------------------------
** Server and accept-fork loop if in server mode
** --------------------------------------------------------------------------------------------------------------------
*/
    if (is_server)
    {
        // RH todo: provide a way for listen loop (server) process to gracefully close and clean up fds
        int master_control_fd = control_fd; // control_fd will become client's fd every loop so make a note of original
    
        char startup_msg[] = "startup";
        if (send(master_control_fd, startup_msg, sizeof(startup_msg)-1, 0) != sizeof(startup_msg)-1)
            ABEND(500, "could not send startup msg down control fd");

        // listen in an accept loop
        int listen_sock = -1;
        {
            union {
                struct sockaddr sa;
                struct sockaddr_in sin;
                struct sockaddr_in6 sin6;
                struct sockaddr_storage ss; 
            } addr ;
         
            if (!is_ipv6) {
                addr.sin.sin_family = AF_INET;
                addr.sin.sin_port = htons(port);
                addr.sin.sin_addr.s_addr = htonl(INADDR_ANY);
                listen_sock = socket(AF_INET, SOCK_STREAM, 0);
            } else {
                addr.sin6.sin6_family = AF_INET6;
                addr.sin6.sin6_addr = in6addr_any;
                addr.sin6.sin6_port = htons(port);
                listen_sock = socket(AF_INET6, SOCK_STREAM, 0);
            }

            if (listen_sock < 0) {
                perror("Unable to create socket");
                exit(EXIT_FAILURE);
            }

            int optval = 1;
            setsockopt(listen_sock, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));

            if (bind(listen_sock, (struct sockaddr*)&(addr.sa), sizeof(addr)) < 0)
                ABEND(700, "could not bind stocket for listen");

            if (listen(listen_sock, 1) < 0) 
                ABEND(701, "listen() failed");
        }

        for(;;) {

            client_fd = accept(listen_sock, (struct sockaddr*)&client_addr, &client_addr_len);
            if (client_fd < 0) {
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
                close(client_fd);
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
                    fprintf(stderr,
                        "could not send control line fd for newly connected client down master control line");
                    close(client_fd);
                    close(child_control_fd[0]);
                    close(child_control_fd[1]);
                    continue;
                }    
            }

            // todo: count clients / sub processes
            if (fork()) {
                close(child_control_fd[0]);
                close(child_control_fd[1]);
                close(client_fd);
                continue;
            }
            
            // fall through to this point in code indicates this is a child process
            close(child_control_fd[1]);
            control_fd = child_control_fd[0];
            close(listen_sock);

            // send pid down the line as a four byte integer
            uint32_t to_send = (uint32_t)getpid();
            if (send(control_fd, (unsigned char*)(&to_send), sizeof(uint32_t), 0) < sizeof(uint32_t))
                ABEND(333, "could not send pid down control line");

            break;
        }
    }
/*
** --------------------------------------------------------------------------------------------------------------------
** Connect out if in client mode
** --------------------------------------------------------------------------------------------------------------------
*/
    if (!is_server)
    {

        // as a websocket client we are required to generate masking keys
        // so open this fd to urandom and leave it open
        urand_fd = open("/dev/urandom", O_RDONLY);
        if (!urand_fd)
            ABEND(301, "could not open /dev/urandom");


        struct addrinfo* res;
        char p[10];
        snprintf(p, 10, "%d", port);
        printf("resolving host: %.*s\n", sizeof(host), host);
        int rc = getaddrinfo(host, p, NULL, &res);
        if (rc)
            ABEND(3, gai_strerror(rc));

        if (res->ai_addrlen > sizeof(client_addr))
            ABEND(4, "size of connect-to address exceeds address buffer");

        memcpy(&client_addr, res->ai_addr, res->ai_addrlen);
        client_addr_len = res->ai_addrlen;

        char connect_ip[50];
        if (res->ai_family == AF_INET6) 
            inet_ntop(AF_INET6, &client_addr.sin6.sin6_addr, connect_ip, sizeof(connect_ip));
        else 
            inet_ntop(AF_INET, &client_addr.sin.sin_addr, connect_ip, sizeof(connect_ip));

        printf("ip: %.*s\n", sizeof(connect_ip), connect_ip);

        client_fd = socket( res->ai_family, SOCK_STREAM, 0 );
        if (connect(client_fd, (struct sockaddr *)&client_addr, client_addr_len))
        {
            perror("Unable to connect");
            ABEND(5, "can't connect");
        }
        printf("connected\n");
        ws_state = -2; // this state means we need to send an upgrade request
    }

/*
** ------------------------------------------------------------------------------------------------------------
** Set up anonymous buffers for new client
** ------------------------------------------------------------------------------------------------------------
*/
    {
        // rotating (swapping) buffers in and out
        // both processes have the following
        // 1. a buffer currently locked by the opposite process (being read)
        // 2. a buffer currently being written to by this process (being written)
        // 3. the buffer being written to will only be handed to the other process
        //    when the buffer being read from is handed back 
        //    this is so there is always a buffer to write into
        ws_buffer_fd[0] = memfd_create("hpws_to_core_1", 0);
        ws_buffer_fd[1] = memfd_create("hpws_to_core_2", 0);
        ws_buffer_fd[2] = memfd_create("core_to_hpws_1", 0);
        ws_buffer_fd[3] = memfd_create("core_to_hpws_2", 0);

        // these record which buffers are awaiting an ack
        
        for (int i = 0; i < 4; ++i) {
            if (ws_buffer_fd[i] < 0) {
                perror("failed to create memfd\n");
                return 1;
            }
            if (ftruncate(ws_buffer_fd[i], ws_buffer_length)) {
                perror("could not ftruncate memfd\n");
                return 1;
            }
            void* mapping =
                mmap( NULL, ws_buffer_length, PROT_WRITE | PROT_READ,
                      MAP_SHARED, ws_buffer_fd[i], 0 );
            if (mapping == (void*)-1) {
                perror("failed to mmap memfd\n");
                return 1;
            }
            ws_buffer[i] = mapping;
            if (DEBUG)
                printf("fd %d: %d - %x\n", i, ws_buffer_fd[i], mapping);   
        }

        ws_buf_decode = ws_buffer[0];
    }
/*
** ------------------------------------------------------------------------------------------------------------
** Set up control line and send buffer handles using SCM_RIGHTS
** ------------------------------------------------------------------------------------------------------------
*/
    {
        // once we fall through to this point in execution the program is the same for
        // 1) a connected client that was just accept()ed
        // 2) a connected client that was just connect()ed
        // the control_fd messages are the same, the buffers are the same and the proxy is the same

        // first thing the new client always does is send its address to the control line
        if (send(control_fd, (void*)&client_addr, sizeof(client_addr), 0) != sizeof(client_addr))
            ABEND(6, "could not send client_addr to control fd");

        if (DEBUG)
            printf("connection established\n");

             
        // second thing the new client does is send its buffer fd's to the control line
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

/*
** ------------------------------------------------------------------------------------------------------------
** Set up TLS connection 
** ------------------------------------------------------------------------------------------------------------
*/
    {     
        #define SSL_FAILED(x) (\
            (x) != SSL_ERROR_WANT_WRITE &&\
            (x) != SSL_ERROR_WANT_READ &&\
            (x) != SSL_ERROR_NONE )

        #define SSL_FLUSH_OUT()\
        {\
          ssize_t bytes_read = 0;\
          do {\
            bytes_read = BIO_read(wbio, ssl_buf, sizeof(ssl_buf));\
            if (DEBUG)\
                printf("flushing %d bytes\n", bytes_read);\
            if (bytes_read > 0) {\
                ssl_write_buf = (char*)realloc(ssl_write_buf, ssl_write_len + bytes_read);\
                memcpy(ssl_write_buf + ssl_write_len, ssl_buf, bytes_read);\
                ssl_write_len += bytes_read;\
            }\
            else if (!BIO_should_retry(wbio))\
                GOTO_ERROR("ssl could not enqueue outward bytes", ssl_error);\
          } while (bytes_read > 0);\
        }

        #define SSL_ENQUEUE(buf, len)\
        {\
            ssl_encrypt_buf = (char*)realloc(ssl_encrypt_buf, ssl_encrypt_len + len);\
            memcpy(ssl_encrypt_buf + ssl_encrypt_len, buf, len);\
            ssl_encrypt_len += len; \
        }

        SSL_load_error_strings();
        OpenSSL_add_ssl_algorithms();
       
        { 
            const SSL_METHOD* method = ( is_server ? SSLv23_server_method() : SSLv23_method() );
            ctx = SSL_CTX_new(method);
            if (!ctx) {
                perror("Unable to create SSL context");
                ERR_print_errors_fp(stderr);
                ABEND(8, "could not create ssl context");
            }
        }

        SSL_CTX_set_ecdh_auto(ctx, 1);
        if (is_server) {
            /* Set the key and cert */
            if (SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) <= 0) {
                ERR_print_errors_fp(stderr);
                ABEND(9, "could not set ssl cert file");
            }
            if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0 ) {
                ERR_print_errors_fp(stderr);
                ABEND(10, "could not set ssl key file");
            }
        }

        ssl = SSL_new(ctx);
        rbio = BIO_new(BIO_s_mem()); /* SSL reads from, we write to. */
        wbio = BIO_new(BIO_s_mem()); /* SSL writes to, we read from. */
        SSL_set_bio(ssl, rbio, wbio);

        status = 0;

        fdset[0].events =  POLLERR | POLLHUP | POLLNVAL | POLLIN ;
        
        if (is_server)
            SSL_set_accept_state(ssl); 
        else {
            SSL_set_connect_state(ssl);
            if (DEBUG)
                printf("trying to start ssl handshake\n");
            int n = SSL_do_handshake(ssl);
            ERR_print_errors_fp(stderr);
            int e = SSL_get_error(ssl, n);
            SSL_FLUSH_OUT()
        }
    } 
/*
** ------------------------------------------------------------------------------------------------------------
** Main event loop
** ------------------------------------------------------------------------------------------------------------
*/


    fdset[0].fd = client_fd;
    fdset[1].fd = control_fd;

    for (;;)
    {
        fdset[0].events &= ~POLLOUT;
        fdset[1].events = POLLIN;

        if (ssl_write_len > 0)
            fdset[0].events |=  POLLOUT;
     
        if (!poll(&fdset[0], 2, -1))
            continue;

        // check for errors in the socket
        if (fdset[0].revents & (POLLERR | POLLHUP | POLLNVAL) || read(client_fd, ssl_buf, 0))
        {
            int error = 0;
            socklen_t errlen = sizeof(error);
            getsockopt(client_fd, SOL_SOCKET, SO_ERROR, (void *)&error, &errlen);
            fprintf(stderr, "socket error: %d\n", error);
            GOTO_ERROR("websocket err hup nval", client_closed);   
        }

        // check for errors in the control line
        int dummy_buf[1];
        if (fdset[1].revents & (POLLERR | POLLHUP | POLLNVAL) || read(control_fd, dummy_buf, 0))
                GOTO_ERROR("control fd err hup nval", control_closed);   

        // ------------------------------------------------------------------------------------------------------------
        // incoming  message on the control line
        // ------------------------------------------------------------------------------------------------------------
        if ( fdset[1].revents & POLLIN )
        {
            char control_msg[12];
            int bytes_read = recv(control_fd, control_msg, sizeof(control_msg), 0);
            if (bytes_read < 1)
                GOTO_ERROR("received invalid control message or control fd has broken or closed", control_closed);
                
            switch (*control_msg)
            {
                case 'c': // close
                    GOTO_ERROR("control ordered close", force_closed);
                    break;

                case 'a': // ack, we can unlock the specified buffer
                    {
                    if (bytes_read != 2 || ( control_msg[1] != '0' && control_msg[1] != '1' ))
                        GOTO_ERROR("received invalid 'c' message from control fd", control_error);
                    
                    if (DEBUG)
                        printf("received ack for buffer %c\n", control_msg[1]);

                    int unlock = control_msg[1] - '0';
                    ws_buffer_lock[unlock] = 0;
                    if (ws_buf_decode == NULL)
                        ws_buf_decode =  ws_buffer[unlock]; 
                    }
                    break;
                
                // ------------------------------------------------------------------------------------------------------------
                // incoming control fd message -> outgoing websocket message
                // ------------------------------------------------------------------------------------------------------------
                case 'o': // outgoing frame on buffer x, of size y
                {
                    if (bytes_read != 6 || 
                        ( control_msg[1] != '0' && control_msg[1] != '1' )
                    )
                    {
                        fprintf(stderr, 
                                "o message received from hp:-----\n%.*s\n----------\n", bytes_read, control_msg);
                        GOTO_ERROR("received invalid 'o' message from control fd", control_error);
                    }
                    unsigned char binary = control_msg[1] - '0';
                    int lock = control_msg[2] - '0' + 2;
                    int size = *((uint32_t*)(control_msg + 3));
                    if (DEBUG)
                        printf(stderr, "OUTGOING MESSAGE RECEIVED FROM HP:\n%.*s\n--------------",
                                size, ws_buffer[lock]);
                    // construct a websocket frame
                    {
                        unsigned char buf[16];
                        buf[0] = 0b10000000 | binary;
                        if (size < 126) {
                            buf[1] = (char)(size) + (is_server ? 0 : 0b10000000); // set masking bit if client
                            SSL_ENQUEUE(buf, 2);
                        }
                        else if (size <= 0xffff)
                        {
                            buf[1] = 126 + (is_server ? 0 : 0b10000000);
                            buf[2] = ( size >> 8 ) & 0xff;
                            buf[3] = ( size >> 0 ) & 0xff;
                            SSL_ENQUEUE(buf, 4);
                        }
                        else
                        {
                            buf[1] = 127 + (is_server ? 0 : 0b10000000);
                            buf[2] = ( size >> 56 ) & 0xff;
                            buf[3] = ( size >> 48 ) & 0xff;
                            buf[4] = ( size >> 40 ) & 0xff;
                            buf[5] = ( size >> 32 ) & 0xff;
                            buf[6] = ( size >> 24 ) & 0xff;
                            buf[7] = ( size >> 16 ) & 0xff;
                            buf[8] = ( size >>  8 ) & 0xff;
                            buf[9] = ( size >>  0 ) & 0xff;
                            SSL_ENQUEUE(buf, 10);
                        }

                        if (!is_server) {
                            // masking key required!
                            unsigned char masking_key[12];
                            if (read(urand_fd, masking_key, 4) != 4)
                                GOTO_ERROR("could not read 4 bytes from /dev/urandom", internal_error); 
                                SSL_ENQUEUE(masking_key, 4);

                            // expand the key to 3 repeats for the block_xor
                            for (int i = 0; i < 4; ++i) {
                                masking_key[i + 4] = masking_key[i];
                                masking_key[i + 8] = masking_key[i];
                            }
                                
                            // XOR over the buffer
                            block_xor(ws_buffer[lock], 0, size, masking_key);
                        }
                     
                        SSL_ENQUEUE(ws_buffer[lock], size);
                        buf[0] = 'a';
                        buf[1] = '0' + lock - 2;
                        if (send(control_fd, buf, 2, 0) != 2)
                            GOTO_ERROR("could not send ack to control fd", control_error);
                    }
                    break;
                }
                default:
                    fprintf(stderr, "unknown control message received `%*.s`\n", bytes_read, control_msg); 
                    GOTO_ERROR("unknown control message", control_error); 
            }
            
        } 


        
        // ------------------------------------------------------------------------------------------------------------
        // outgoing data on the socket
        // ------------------------------------------------------------------------------------------------------------
        if (fdset[0].revents & POLLOUT && ssl_write_len)
        {
            bytes_written = write(client_fd, ssl_write_buf, ssl_write_len);
            if (DEBUG)
                printf("outgoing data %ld\n", bytes_written);
            if (bytes_written <= 0)
                GOTO_ERROR("unable to write encrypted bytes to socket", ssl_error); 
            if (bytes_written < ssl_write_len)
                memmove(ssl_write_buf, ssl_write_buf + bytes_written, ssl_write_len - bytes_written);
            ssl_write_len -= bytes_written;
            ssl_write_buf = (char*)realloc(ssl_write_buf, ssl_write_len);
            continue;
        }

        // ------------------------------------------------------------------------------------------------------------
        // incoming data on the socket
        // ------------------------------------------------------------------------------------------------------------
        if (fdset[0].revents & POLLIN || ws_pending_read)
        {

            if (DEBUG)
                printf("incoming data\n");           

            // either we're here because there is fresh data on the socket that needs to be ingested by SSL or we're
            // here because we already did that previously but there was no free buffer to decode into this branch is
            // the former 
            if (fdset[0].revents & POLLIN)
            {
                bytes_read = read(client_fd, ssl_buf, sizeof(ssl_buf));
                if (bytes_read <= 0) 
                    GOTO_ERROR("client closed connection", client_closed);
                
                bytes_written = BIO_write(rbio, ssl_buf, bytes_read);
                if (bytes_written <= 0)
                    GOTO_ERROR("could not write raw bytes to openssl from incoming socket", ssl_error);
                   
                if ( !SSL_is_init_finished(ssl) ) {
                    if (DEBUG)
                        printf("trying to ssl handshake\n");
                    int n = SSL_do_handshake(ssl);
                    int e = SSL_get_error(ssl, n);
                    SSL_FLUSH_OUT()

                    char buf[1] = { 'r' }; // send 'ready' message
                    if (send(control_fd, buf, 1, 0) != 1)
                        GOTO_ERROR("could not write ready message to control fd", control_error);
                } 
            }

            if (!SSL_is_init_finished(ssl))
                goto skip_ws;


            // --------------------------------------------------------------------------------------------------------
            // incoming websocket data
            // --------------------------------------------------------------------------------------------------------
            {
                #define WS_AT_LEAST( x, bytes_read, wait_for_bytes )\
                {\
                    if (bytes_read < (x))\
                    {\
                        wait_for_bytes = x;\
                        break;\
                    }\
                }

                #define WS_STORE_MASKING_KEY( masking_key, buf, o )\
                {\
                    if (DEBUG)\
                        printf("storing masking key %08X\n", *((uint32_t*)(&buf[o])));\
                    for (int i = 0; i < 12; ++i)\
                        masking_key[i] = buf[ o + (i % 4)];\
                }

                #define WS_SEND_CLOSE_FRAME( reason_code, reason_string )\
                {\
                    if (!ws_sent_close_frame) {\
                        if (DEBUG)\
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
                    if (DEBUG)\
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

                // websocket frame decoding is a state machine running inside the ssl decoding state machine
                for (;;)
                {
                    // we cannot read anything unless we have a buffer to read into, so skip websockets in that case
                    if (ws_buf_decode == NULL)
                    {
                        ws_pending_read = 1;
                        if (DEBUG)
                            printf("skipping websocket  read because there are no free buffers\n");
                        goto skip_ws;
                    }

                    // this state refers to a freshly connect()ed client which needs to send out an upgrade req
                    if ( ws_state == -2 )
                    {
                        unsigned char nonce[16];
                        if (read(urand_fd, nonce, 16) != 16)
                            GOTO_ERROR("could not read /dev/urandom", ws_handshake_error);

                        char nonce_b64[BASE64_LEN(16)];
                        if (!base64_encode(nonce, 16, nonce_b64, sizeof(nonce_b64)))
                            GOTO_ERROR("could not base64 encoded nonce", ws_handshake_error);

                        char request[1024];

                        int snprintf_result = snprintf(request, sizeof(request), 
                            "GET %s HTTP/1.1\r\n"
                            "Host: %s\r\n"
                            "Upgrade: websocket\r\n"
                            "Connection: Upgrade\r\n"
                            "Sec-WebSocket-Key: %s\r\n"
                            "Sec-WebSocket-Version: 13\r\n\r\n",
                            get, host, nonce_b64);

                        if (!(snprintf_result > 0 && snprintf_result < sizeof(request)))
                            GOTO_ERROR("websocket upgrade request longer than buffer, could not connect", 
                                        ws_handshake_error);
                        if (DEBUG)
                            printf("- outgoing websocket upgrade request -\n%s-----------------------------", request);
                    
                        SSL_ENQUEUE(request, snprintf_result);
                        SSL_FLUSH_OUT();

                        ws_state = -1; 
                        goto skip_ws;

                    }

                    // this state is where we wait for a reply to an upgrade request (as a client)
                    if ( ws_state == -1 )
                    {
                        // todo: handle edge case where ws data comes in directly following upgrade, in the same packet
                        int bytes_read = SSL_read( ssl, ws_buf_decode, ws_buffer_length - 1 );
                        if (DEBUG)
                            fprintf(stderr, "--bytes read: %d\n--\n%.*s\n--\n", bytes_read, bytes_read, ws_buf_decode); 
                        if (bytes_read <= 0)
                            goto skip_ws;
                        ws_state = 1;
                        goto skip_ws;
                    }

                    // in this state we are server waiting for an upgrade request from client
                    if ( ws_state == 0 )
                    {
                        // todo: should we loop to ensure a complete http request?
                        int bytes_read = SSL_read( ssl, ws_buf_decode, ws_buffer_length - 1 );
                        if (DEBUG)
                            fprintf(stderr, "--bytes read: %d\n", bytes_read); 
                        if (bytes_read <= 0)
                            goto skip_ws;
                        ws_buf_decode[bytes_read-1] = '\0';

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
                        SSL_FLUSH_OUT()
                        ws_state = 1;
                        goto skip_ws;
                    }


                    // in these state we are still reading the header of a frame
                    if ( ws_state > 0 && ws_state < 3 )
                    {
                        // read into header
                        if (ws_multi_frame_total_bytes_received >= sizeof(ws_buf_header))
                            WS_PROTOCOL_ERROR( "tried to read beyond 14 bytes of header" );

                        ws_read_result = 
                            SSL_read( ssl,
                                ws_buf_header + ws_multi_frame_total_bytes_received + ws_header_back_read,
                                sizeof(ws_buf_header) - ws_multi_frame_total_bytes_received - ws_header_back_read );
                        
                        if (ws_read_result <= 0) {
                            if (!ws_header_back_read)
                                goto skip_ws;
                            ws_read_result = 0;
                        }

                        if (ws_header_back_read) {
                            ws_read_result += ws_header_back_read;
                            ws_header_back_read = 0;
                        }

                        ws_multi_frame_total_bytes_received += ws_read_result;
                    } 

                    // if we are still processing header but need more bytes we will skip
                    if (ws_state < 3 && ws_multi_frame_total_bytes_received < ws_wait_for_bytes)
                    {
                        SSL_FLUSH_OUT();
                        continue;
                    }

                    // in this state we know we have a header but we don't know how long it is yet, so 
                    // read only the first 2 bytes
                    if ( ws_state == 1 )
                    {
                        // read a header, will always have at least 2 bytes
                        WS_AT_LEAST(2, ws_multi_frame_total_bytes_received, ws_wait_for_bytes);

                        if (ws_buf_header[0] & 0b01110000)
                            WS_PROTOCOL_ERROR("rsv1-3 must be 0");

                        // parse opcode            
                        ws_fin = ((ws_buf_header[0] >> 7) & 0x1);

                        ws_opcode = ws_buf_header[0] & 0b00001111; 
                        if (!ws_opcode && ws_fin)
                            WS_PROTOCOL_ERROR("fin bit set on opcode 0");
                        
                        // check mask flag is present
                        if (ws_buf_header[1] >> 7 == 0)
                            WS_PROTOCOL_ERROR("masking flag nil");
             
                        // parse size
                        ws_preliminary_size = ws_buf_header[1] & 0b01111111;

                        if (DEBUG) 
                        {
                            printf("ws header: bytes_read %d ws_opcode %d ws_fin %d ws_preliminary_size %d\n",
                                ws_multi_frame_total_bytes_received, ws_opcode, ws_fin,  ws_preliminary_size );

                            printf("opcode: %d\n", ws_opcode);
                        }
                        switch (ws_opcode) {
                            case 0: // continuation frame
                            case 1: // text frame
                            case 2: // binary frame
                                break;
                            case 8: // close frame
                                {
                                    WS_AT_LEAST(ws_preliminary_size,  ws_multi_frame_total_bytes_received, ws_wait_for_bytes);
                                    ws_received_close_frame = 1;
                                    WS_SEND_CLOSE_FRAME(1000, "Bye!");
                                    // send a 'c' message to the control line
                                    char buf[1] = {'c'};
                                    send(control_fd, buf, 1, 0); // don't care if it doesnt receive it
                                    goto ws_graceful_close;
                                    //GOTO_ERROR("ws closing due to close frame", ws_graceful_close);
                                }
                            case 9: // ping frame
                            case 10:  // pong frame, discard
                                {
                                    // modify the opcode and send it back
                                    WS_AT_LEAST(ws_preliminary_size, ws_multi_frame_total_bytes_received, ws_wait_for_bytes);
                                    if (DEBUG)
                                        printf("ping/pong frame\n");
                                    if (ws_opcode == 9) {        
                                        ws_buf_header[0]++; // its a pong!
                                        if (!ws_sent_close_frame)
                                            SSL_ENQUEUE(ws_buf_header, ws_preliminary_size);
                                    }
                                    ws_state  = 1;
                                    ws_wait_for_bytes = 2;
                                    ws_multi_frame_total_bytes_received = 0;
                                    break;
                                }
                            default:
                                {
                                    WS_SEND_CLOSE_FRAME(1002, "Invalid opcode");
                                    GOTO_ERROR("ws invalid opcode", ws_protocol_error);
                                }
                        }
                        ws_state = 2;
                        SSL_FLUSH_OUT();
                        // this state drops through to the next
                    }

                    // in this state we have read a preliminary size from state 1 and we know how much more header
                    // to read  
                    if (ws_state == 2)
                    {
                        int header_size = 0;
                        if (ws_preliminary_size == 126) {
                            if (DEBUG)
                                printf("[[PATH A]]  %02X %02X %02X %02X\n", ws_buf_header[0], ws_buf_header[1],
                                        ws_buf_header[2], ws_buf_header[3]);
                            WS_AT_LEAST(8, ws_multi_frame_total_bytes_received, ws_wait_for_bytes);
                            ws_payload_bytes_expected=  
                                ((uint64_t)ws_buf_header[2] << 8) + ((uint64_t)ws_buf_header[3] << 0);
                            WS_STORE_MASKING_KEY(ws_masking_key, ws_buf_header, 4);
                            if (DEBUG)
                                printf("ws_payload_bytes_expected %lu\n", ws_payload_bytes_expected);
                            header_size = 8; 
                        } else if (ws_preliminary_size == 127) {
                            if (DEBUG)
                                printf("[[PATH B]]\n");
                            WS_AT_LEAST(14, ws_multi_frame_total_bytes_received, ws_wait_for_bytes);
                            ws_payload_bytes_expected = 
                                ((uint64_t)ws_buf_header[2] << 56) + ((uint64_t)ws_buf_header[3] << 48) + 
                                ((uint64_t)ws_buf_header[4] << 40) + ((uint64_t)ws_buf_header[5] << 32) + 
                                ((uint64_t)ws_buf_header[6] << 24) + ((uint64_t)ws_buf_header[7] << 16) + 
                                ((uint64_t)ws_buf_header[8] << 8) +  ((uint64_t)ws_buf_header[9] << 0); 
                            WS_STORE_MASKING_KEY(ws_masking_key, ws_buf_header, 10);
                            header_size = 14; 
                        } else {
                            if (DEBUG)
                                printf("[[PATH C]]\n");
                            WS_AT_LEAST(6, ws_multi_frame_total_bytes_received, ws_wait_for_bytes);
                            ws_payload_bytes_expected = ws_preliminary_size;
                            WS_STORE_MASKING_KEY(ws_masking_key, ws_buf_header, 2);
                            header_size = 6; 
                        }          
                    
                        if (DEBUG)
                            printf("payload bytes expected:  %d\n",ws_payload_bytes_expected); 

                        // memcpy unused or extra header bytes (which are actually payload) into ws_buf_decode
                        if (ws_multi_frame_total_bytes_received > header_size) {
                            size_t copied_payload = ws_multi_frame_total_bytes_received - header_size;
                            if (DEBUG)
                                printf("copying %d bytes of payload\n", copied_payload);
                            memcpy( ws_buf_decode + ws_payload_upto, ws_buf_header + header_size, copied_payload );
                            ws_back_read = copied_payload;
                        } 
                        ws_multi_frame_total_bytes_received = 0;
                        ws_state = 3;
                        SSL_FLUSH_OUT();
                        // this state drops through to the next
                    }
                    

                    // in this state we are reading payload and decoding it according to masking key
                    if (ws_state == 3)
                    {

                        ws_pending_read = 0;

                        ws_payload_bytes_remaining =
                            ws_payload_bytes_expected - ws_payload_upto;
                        
                        // read into decode buffer
                        int buffer_bytes_left =
                                ws_buffer_length - ws_multi_frame_total_bytes_received -
                                ws_payload_upto - 8 - ws_back_read;
                        
                        if (ws_payload_bytes_remaining > buffer_bytes_left)
                            WS_PROTOCOL_ERROR( "payload message exceeded maximum messagesize" ) ;
                        // RH TODO make this a ws maxsize error 

                        ws_read_result =
                            SSL_read( ssl,
                                      ws_buf_decode + ws_multi_frame_total_bytes_received + ws_back_read,
                                      ws_payload_bytes_remaining );

                        if (ws_read_result <= 0) {
                            if (!ws_back_read)
                                goto skip_ws;
                            ws_read_result = 0;
                        }

                        if (ws_back_read) {
                            ws_read_result += ws_back_read;
                            ws_back_read = 0;
                        }
                        
                        if (DEBUG)
                            printf("== bytes read : %d\n== payload_bytes_remaining: %d\n",
                                    ws_read_result, ws_payload_bytes_remaining );
               
                        // there can be overshoot due to backread,
                        // so in this scenario we copy back into header buf

                        if ( ws_payload_bytes_remaining < ws_read_result ) {
                            int spare_header_bytes =  ( ws_read_result - ws_payload_bytes_remaining );
                            if (DEBUG)
                                printf("== copying spare header bytes %d\n", spare_header_bytes);
                            if (spare_header_bytes > 14)
                                // this should never happen but catch it incase some bug makes it happen
                                WS_PROTOCOL_ERROR( "could not back-backcopy header bytes from decode buffer, "
                                                   "header bytes too long");
                            memcpy( ws_buf_header,
                                    ws_buf_decode + ws_multi_frame_total_bytes_received + ws_payload_upto + 
                                    ws_payload_bytes_remaining, spare_header_bytes );  

                            ws_read_result = ws_payload_bytes_remaining;

                            ws_header_back_read = spare_header_bytes;
                        }

                        ws_multi_frame_total_bytes_received += ws_read_result;
                            
                        ws_payload_next = ws_read_result + ws_payload_upto;
                        

                        if (ws_read_result >= ws_payload_bytes_remaining) {
                            if (DEBUG)
                                printf("[[PATH 1]]\n");
                            ws_payload_next = ws_payload_bytes_remaining + ws_payload_upto;
                            ws_state = 4;
                        }         

                        if (DEBUG)
                            printf("masking key loop:  %08X - offset: %d, %d - %d, "
                                   "(total)ws_multi_frame_total_bytes_received: %d\n",
                                (*(uint32_t*)(ws_masking_key)), (ws_payload_upto % 4), ws_payload_upto,
                                ws_payload_next, ws_multi_frame_total_bytes_received);
                        /*
                            Efficient XOR processing loop
                            First iterate to an 8 byte boundary one byte a time
                            Next perform efficient 8 byte XORs to the final 8 byte boundary
                            Finally iterate one byte at a time to the final byte boundary
                        */

                        block_xor(ws_buf_decode, ws_payload_upto, ws_payload_next, ws_masking_key);
                        
                        if (ws_state != 4)
                              ws_payload_upto = ws_payload_next;

                        SSL_FLUSH_OUT();
                        // this state falls through to the next
                        
                    }

                    // in this state we have received a complete message 
                    if (ws_state == 4) 
                    {
                        if (ws_fin)
                        {
                            // final frame in the fragment so we need to send a control line msg and swap buffers
                            if (DEBUG) {
                                static int line = 0;
                                int to_print = 20;
                                if ((int)ws_payload_bytes_expected < to_print)
                                    to_print = (int)ws_payload_bytes_expected;
                                printf(
                                        "(%05d: %02d/%02d - %d offset: %d packet: `%.*s`%s`%.*s`\n", 
                                        line++,
                                        ws_payload_bytes_remaining,
                                        ws_payload_bytes_expected, 
                                        ws_fin,
                                        ws_payload_bytes_expected, 
                                        to_print,
                                        ws_buf_decode,
                                        ( ((int)ws_payload_bytes_expected < to_print) ? "": "..." ),
                                        ( ((int)ws_payload_bytes_expected < to_print) ? 0: 20 ),
                                        ( ((int)ws_payload_bytes_expected < to_print) ? "": (ws_buf_decode + ws_payload_bytes_expected - 20))); 
                                

                            }

                            int sending_buf = ( ws_buf_decode == ws_buffer[0] ? 0 : 1 );
            
                            char control_msg[6] = { 'o', '0' + sending_buf, 0, 0, 0, 0 };
                            *((uint32_t*)(control_msg+2)) = ws_payload_next;

                            if (DEBUG)
                                printf("sending o msg len: %d\n", ws_payload_next);

                            send(control_fd, control_msg, 6, 0);
                            // do the buffer swap
                            ws_buffer_lock[sending_buf] = 1;
                            int next_buf = ( sending_buf + 1 ) % 2; // this can be extended to more than 2 buffers
                            if (ws_buffer_lock[ next_buf ]) {
                                // both buffers are now locked
                                ws_buf_decode = NULL;
                            } else {
                                ws_buf_decode = ws_buffer[next_buf];
                            }

                            ws_payload_upto = 0;
                            ws_multi_frame_total_bytes_received = 0;
                        } 

                        ws_state = 1;
                        SSL_FLUSH_OUT();
                        // loops back to start incase another frame starts in this packet
                    }

                    if (ws_state > 4 || ws_state < -2) 
                    {
                        WS_SEND_CLOSE_FRAME(1001, "Internal error");
                        GOTO_ERROR("ws internal error", ws_protocol_error);
                    }
                }
            }
            // --------------------------------------------------------------------------------------------------------
            // end of incoming websocket data
            // --------------------------------------------------------------------------------------------------------

            skip_ws:;
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

    }

    ws_handshake_error:;
    ws_protocol_error:;
    ws_graceful_close:;
    socket_error:;
    ssl_error:;
    client_closed:;
    control_closed:;
    control_error:;
    force_closed:;
    internal_error:;


    if (DEBUG)
        printf("client finished %d\n", getpid());
    close(client_fd);
    close(control_fd);
    for (int i = 0; i < 4; ++i)
        if (ws_buffer_fd[i] > -1)
            close(ws_buffer_fd[i]);
    EVP_cleanup();
    SSL_free(ssl);
    free(ssl_write_buf);
    free(ssl_encrypt_buf);

    if (urand_fd > -1)
        close(urand_fd);

    return 0;
}


unsigned char * base64_encode( unsigned char* src, size_t len, unsigned char* out, size_t out_len ) 
{
    // base64 code from http://web.mit.edu/freebsd/head/contrib/wpa/src/utils/base64.c
    static const unsigned char base64_table[65] =
	    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
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


void block_xor(unsigned char* restrict buf, uint64_t start, uint64_t end, unsigned char* masking_key_x3)
{

    uint64_t i = start;
    uint64_t start_boundary =  start + (8 - (start % 8));
    uint64_t end_boundary =  end - (end % 8);

    if (start_boundary < end_boundary)
    {

        for (; i < start_boundary; ++i)
             *(buf + i) ^= masking_key_x3[i % 4];
        
        // this is a further optimisation since incrementing by 8 doesnt change %4
        uint8_t key_offset = i % 4; 

        for(; i < end_boundary; i += 8)
            *(uint64_t*)(buf + i) ^=
                *((uint64_t*)(masking_key_x3 + key_offset));

        for (; i < end; ++i) 
             *(buf + i) ^= ((unsigned char*)masking_key_x3)[ i % 4 ];

    } else 
        for (; i < end; ++i)
             *(buf + i) ^= ((unsigned char*)masking_key_x3)[i % 4];
}
