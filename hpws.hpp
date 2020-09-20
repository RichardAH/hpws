#ifndef HPWS_INCLUDE
#define HPWS_INCLUDE
#include <signal.h>
#include <poll.h>

#include <variant>
#include <optional>
#include <alloca.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/mman.h>
#include <unistd.h>
#include <vector>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/wait.h>

namespace hpws {
    /*typedef enum e_retcode {
        SUCCESS
    } retcode;
    */
    using error = std::pair<int, std::string>;

    // used when waiting for messages that should already be on the pipe
    #define HPWS_SMALL_TIMEOUT 10
    // used when waiting for server process to spawn
    #define HPWS_LONG_TIMEOUT 1500 

    typedef union {
        struct sockaddr sa;
        struct sockaddr_in sin;
        struct sockaddr_in6 sin6;
        struct sockaddr_storage ss;
    } addr_t ;


    class server;

    class client {

    private: 
        uint32_t child_pid = 0;  // if this client was created by a connect this is set
        // this value can't be changed once it's established between the processes
        uint32_t max_buffer_size;
        bool moved = false;
        addr_t endpoint;
        int control_line_fd;
        int buffer_fd[4]; // 0 1 - in buffers, 2 3 - out buffers
        void* buffer[4];
        bool ready = false;

        // private constructor
        client( 
            addr_t endpoint,
            int control_line_fd,
            uint32_t max_buffer_size,
            int child_pid,
            int buffer_fd[4],
            void* buffer[4]) : 
            endpoint(endpoint),
            control_line_fd (control_line_fd),
            max_buffer_size (max_buffer_size),
            child_pid(child_pid)
        {
            for (int i = 0; i < 4; ++i) {
                this->buffer[i] = buffer[i];
                this->buffer_fd[i] = buffer_fd[i];
            }

            printf("child constructed pid = %d\n", child_pid);
        } 


    public:


        // No copy constructor
        client(const client&) = delete;

        // only a move constructor
        client ( client&& old ) : 
            child_pid(old.child_pid), 
            max_buffer_size(old.max_buffer_size),
            endpoint(old.endpoint),
            control_line_fd(old.control_line_fd),
            ready(old.ready)
        {
            old.moved = true;
            for (int i = 0; i < 4; ++i) {
                this->buffer[i] = old.buffer[i];
                this->buffer_fd[i] = old.buffer_fd[i];
            }
        }

        ~client() {
            if (!moved) {

                // RH TODO ensure this pid terminates by following up with a SIGKILL
                if (child_pid > -1)
                    kill(child_pid, SIGTERM);
               
                for (int i = 0; i < 4; ++i) {
                    munmap(buffer[i], max_buffer_size);
                    close(buffer_fd[i]);
                }
                
                close(control_line_fd);
            }
        } 
        
        std::variant<std::string_view, error> read()
        {

            char buf[32];
            int bytes_read = 0;

            read_start:;
            bytes_read = recv(control_line_fd, buf, sizeof(buf), 0);
            if (bytes_read < 1)  {
                perror("recv");
                return error { 1,  "control line could not be read" }; // todo clean up somehow?
            }

            if (buf[0] == 'r') {
                ready = true;
                goto read_start;
            }

            if (!ready)
                return error { 11, "received a message other than 'r' when client state not ready" };

            switch ( buf[0] )
            {
                case 'o':
                    {
                    // there's a pending buffer for us
                    uint32_t len = *((uint32_t*)(buf+2));
                    int bufno = buf[1] - '0';
                    if (bufno != 0 && bufno != 1)
                        return error { 3, "invalid buffer in 'o' command sent by hpws" };
               
                    /*fprintf(stderr, "read(%d) ---\n", len);
                    for (uint32_t i = 0; i < len; ++i) 
                        putc(((char*)(buffer[bufno]))[i], stderr);
                    fprintf(stderr, "\n---\n");
                    */
                    return std::string_view { (const char*)(buffer[bufno]), len };
                    }
                    break;
                case 'a':
                    break;
                case 'c':
                    return error { 1000, "ws closed" };
                    break;
                default:
                    printf("read control message: `%.*s`\n",  bytes_read, buf);
                    return error { 2, "unknown control line command was sent by hpws" };
            }
        }

        std::optional<error> ack(std::string_view from_read)  {
            char msg[2] = { 'a', '0' };
            if (from_read.data() == buffer[1]) msg[1]++;
            if (send(control_line_fd, msg, 2, 0) < 2)
                return error { 10, "could not send ack down control line"};
            return std::nullopt;

        }

        static std::variant<client, error> connect (
            std::string_view bin_path,
            uint32_t max_buffer_size,
            std::string_view host, 
            uint16_t port,
            std::vector<std::string_view> argv  )
        {

            #define HPWS_CONNECT_ERROR(code, msg)\
            {\
                error_code = code;\
                error_msg = msg;\
                goto connect_error;\
            }

            int error_code = -1;
            const char* error_msg = NULL;
            int fd[2] = {-1, -1}; 
            int pid = -1;            
            int count_args = 10 + argv.size();
            char const ** argv_pass = NULL;

            if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fd))
                HPWS_CONNECT_ERROR(100, "could not create unix domain socket pair");

            // construct the arguments
            char shm_size[32];

            if (snprintf(shm_size, 32, "%d", max_buffer_size) <= 0)
                HPWS_CONNECT_ERROR(90, "couldn't write shm size to string");
 
            char port_str[6];
            if (snprintf(port_str, 6, "%d", port) <= 0)
                HPWS_CONNECT_ERROR(91, "couldn't write port to string");
            
            argv_pass = 
                reinterpret_cast<char const **>(alloca(sizeof(char*)*count_args));
            {
                int upto = 0;
                argv_pass[upto++] = bin_path.data();
                argv_pass[upto++] = "--client";
                argv_pass[upto++] = "--maxmsg";
                argv_pass[upto++] = shm_size;
                argv_pass[upto++] = "--host";
                argv_pass[upto++] = host.data();
                argv_pass[upto++] = "--port";
                argv_pass[upto++] = port_str;
                argv_pass[upto++] = "--cntlfd";
                argv_pass[upto++] = "3";
                for ( std::string_view& arg : argv )
                    argv_pass[upto++] = arg.data();
                argv_pass[upto] = NULL; 
            }

            pid = vfork();

            if (pid) {

                // --- PARENT

                close(fd[1]);

                int child_fd = fd[0];
                    
                int flags = fcntl(child_fd, F_GETFD, NULL);
                if (flags < 0)
                    HPWS_CONNECT_ERROR(101, "could not get flags from unix domain socket");

                flags |= FD_CLOEXEC;
                if (fcntl(child_fd, F_SETFD, flags))
                    HPWS_CONNECT_ERROR(102, "could notset flags for unix domain socket");

                // we will set a timeout and wait for the initial startup message from hpws client mode
                struct pollfd pfd;
                int ret;

                pfd.fd = child_fd;
                pfd.events = POLLIN;
                ret = poll(&pfd, 1, HPWS_LONG_TIMEOUT); // default= 1500 ms timeout

                // timeout or error
                if (ret < 1)
                    HPWS_CONNECT_ERROR(1, "timeout waiting for hpws connect message");

                printf("waiting for addr_t\n");
                // first thing we'll receive is the sockaddr union
                addr_t child_addr;

                int bytes_read =
                    recv(child_fd, (unsigned char*)(&child_addr), sizeof(child_addr), 0);            

                if (bytes_read < sizeof(child_addr))
                    HPWS_CONNECT_ERROR(202, "received message on control line was not sizeof(addr_t)");

                printf("waiting for buffer fds\n");
                // second thing we will receive is the four fds for the buffers
                int buffer_fd[4]  =  { -1, -1, -1, -1 };
                void* mapping[4];
                {
                    struct msghdr child_msg = { 0 };
                    memset(&child_msg, 0, sizeof(child_msg));
                    char cmsgbuf[CMSG_SPACE(sizeof(int)*4)];
                    child_msg.msg_control = cmsgbuf;
                    child_msg.msg_controllen = sizeof(cmsgbuf);

                    int bytes_read = 
                        recvmsg(child_fd, &child_msg, 0);
                    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&child_msg);
                    if (cmsg == NULL || cmsg -> cmsg_type != SCM_RIGHTS)
                        HPWS_CONNECT_ERROR(203, "non-scm_rights message sent on accept child control line");
                    memcpy(&buffer_fd, CMSG_DATA(cmsg), sizeof(buffer_fd));
                    for (int i = 0; i < 4; ++i) {
                        //fprintf(stderr, "scm passed buffer_fd[%d] = %d\n", i, buffer_fd[i]);
                        if (buffer_fd[i] < 0)
                            HPWS_CONNECT_ERROR(203, "child accept scm_rights a passed buffer fd was negative"); 
                        mapping[i] = 
                            mmap( 0, max_buffer_size, PROT_READ | PROT_WRITE, MAP_SHARED, buffer_fd[i], 0 );
                        if (mapping[i] == (void*)(-1))
                            HPWS_CONNECT_ERROR(204, "could not mmap scm_rights passed buffer fd");
                    }
                }
                printf("waiting for 'r'\n");

                // now we wait for a 'r' ready message or for the socket/client to die
                ret = poll(&pfd, 1, HPWS_LONG_TIMEOUT); // default= 1500 ms timeout

                char rbuf[1];
                bytes_read = recv(fd[0], rbuf,sizeof(rbuf), 0); 
                if (bytes_read < 1)
                    HPWS_CONNECT_ERROR(2, "nil message sent by hpws on startup");

                if (rbuf[0] = 'r') 
                    HPWS_CONNECT_ERROR(3, "unexpected content in message sent by hpws client mode on startup");
                
                return client {
                    child_addr,
                    child_fd,
                    max_buffer_size,
                    pid,
                    buffer_fd,
                    mapping
                };

            } else {
          
                // --- CHILD
                
                close(fd[0]);
                
                // dup fd[1] into fd 3
                dup2(fd[1], 3);
                close(fd[1]);
                    
                // we're assuming all fds above 3 will have close_exec flag
                execv(bin_path.data(), (char* const*)argv_pass);
                // we will send a nil message down the pipe to help the parent know somethings gone wrong
                char nil[1];
                nil[0] = 0;
                send(3, nil, 1, 0);
                exit(1); // execl failure as child will always result in exit here
            
            }
            
 
            connect_error:;

                // NB: execution to here can only happen in parent process            
                // clean up any mess after error
                if (pid > 0) 
                    kill(pid, SIGKILL); /* RH TODO change this to SIGTERM and set a timeout? */
                    int status;
                    waitpid(pid, &status, 0 /* should we use WNOHANG? */);
                if (fd[0] > 0)
                    close(fd[0]);
                if (fd[1] > 0)
                    close(fd[1]);
                
                return error{error_code, std::string{error_msg}};

    
        }
        friend class server;
    };

    class server {

    private:
        int server_pid_;
        int master_control_fd_;  
        uint32_t max_buffer_size_;

        //  private constructor
        server ( int server_pid, int master_control_fd, uint32_t max_buffer_size ) 
        : server_pid_(server_pid), master_control_fd_(master_control_fd), max_buffer_size_(max_buffer_size) {}
    public:
        
        int server_pid() {
            return server_pid_;
        }

        int master_control_fd() {
            return master_control_fd_;
        }

        uint32_t max_buffer_size() {
            return max_buffer_size_;
        }


        std::variant<client, error> accept()
        {
            #define HPWS_ACCEPT_ERROR(code, msg)\
                { return error {code, msg}; }

            int child_fd = -1;
            {
                struct msghdr child_msg = { 0 };
                memset(&child_msg, 0, sizeof(child_msg));
                char cmsgbuf[CMSG_SPACE(sizeof(int))];
                child_msg.msg_control = cmsgbuf;
                child_msg.msg_controllen = sizeof(cmsgbuf);

                int bytes_read = 
                    recvmsg(this->master_control_fd_, &child_msg, 0);
                struct cmsghdr *cmsg = CMSG_FIRSTHDR(&child_msg);
                if (cmsg == NULL || cmsg -> cmsg_type != SCM_RIGHTS)
                    HPWS_ACCEPT_ERROR(200, "non-scm_rights message sent on master control line");
                memcpy(&child_fd, CMSG_DATA(cmsg), sizeof(child_fd));
                if (child_fd < 0)
                    HPWS_ACCEPT_ERROR(201, "scm_rights passed fd was negative"); 
            }
            
            // read info from child control line with a timeout 
            struct pollfd pfd;
            int ret;

            pfd.fd = child_fd;
            pfd.events = POLLIN;
            ret = poll(&pfd, 1, HPWS_SMALL_TIMEOUT); // 1 ms timeout

            // timeout or error
            if (ret < 1)
                return error{202, "timeout waiting for hpws accept child message"};

            // first thing we'll receive is the pid of the client
            uint32_t pid = 0;
            if (recv(child_fd, (unsigned char*)(&pid), sizeof(pid), 0) < sizeof(pid))
                HPWS_ACCEPT_ERROR(212, "did not receive expected 4 byte pid of child process on accept");

            // second thing we'll receive is IP address structure of the client
            addr_t buf;
            int bytes_read =
                recv(child_fd, (unsigned char*)(&buf), sizeof(buf), 0);            

            if (bytes_read < sizeof(buf))
                return error{202, "received message on master control line was not sizeof(sockaddr_in6)"};

            // third thing we will receive is the four fds for the buffers
            int buffer_fd[4]  =  { -1, -1, -1, -1 };
            void* mapping[4];
            {
                struct msghdr child_msg = { 0 };
                memset(&child_msg, 0, sizeof(child_msg));
                char cmsgbuf[CMSG_SPACE(sizeof(int)*4)];
                child_msg.msg_control = cmsgbuf;
                child_msg.msg_controllen = sizeof(cmsgbuf);

                int bytes_read = 
                    recvmsg(child_fd, &child_msg, 0);
                struct cmsghdr *cmsg = CMSG_FIRSTHDR(&child_msg);
                if (cmsg == NULL || cmsg -> cmsg_type != SCM_RIGHTS)
                    return error{203, "non-scm_rights message sent on accept child control line"};
                memcpy(&buffer_fd, CMSG_DATA(cmsg), sizeof(buffer_fd));
                for (int i = 0; i < 4; ++i) {
                    //fprintf(stderr, "scm passed buffer_fd[%d] = %d\n", i, buffer_fd[i]);
                    if (buffer_fd[i] < 0)
                        return error{203, "child accept scm_rights a passed buffer fd was negative"}; 
                    mapping[i] = 
                        mmap( 0, max_buffer_size_, PROT_READ | PROT_WRITE, MAP_SHARED, buffer_fd[i], 0 );
                    if (mapping[i] == (void*)(-1))
                        return error{204, "could not mmap scm_rights passed buffer fd"};
                }
            }

            return client {
                buf,
                child_fd,
                max_buffer_size_,
                pid,
                buffer_fd,
                mapping
            };
    
        }
    
        static std::variant<server, error> create(
            std::string_view bin_path,
            uint32_t max_buffer_size,
            uint16_t port,
            uint32_t max_con,
            uint16_t max_con_per_ip,
            std::string_view cert_path,
            std::string_view key_path,
            std::vector<std::string_view> argv //additional_arguments 
        ){
            #define HPWS_SERVER_ERROR(code, msg)\
            {\
                error_code = code;\
                error_msg = msg;\
                goto server_error;\
            }

            int error_code = -1;
            const char* error_msg = NULL;
            int fd[2] = {-1, -1}; 
            int pid = -1;            
            int count_args = 17 + argv.size();
            char const ** argv_pass = NULL;

            if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fd))
                HPWS_SERVER_ERROR(100, "could not create unix domain socket pair");

            // construct the arguments
            char shm_size[32];

            if (snprintf(shm_size, 32, "%d", max_buffer_size) <= 0)
                HPWS_SERVER_ERROR(90, "couldn't write shm size to string");
 
            char port_str[6];
            if (snprintf(port_str, 6, "%d", port) <= 0)
                HPWS_SERVER_ERROR(91, "couldn't write port to string");

            char max_con_str[11];
            if (snprintf(max_con_str, 11, "%d", max_con) <= 0)
                HPWS_SERVER_ERROR(92, "couldn't write max_con to string");

            char max_con_per_ip_str[6];
            if (snprintf(max_con_per_ip_str, 6, "%d", max_con_per_ip) <= 0)
                HPWS_SERVER_ERROR(93, "couldn't write max_con_per_ip to string");

            argv_pass = 
                reinterpret_cast<char const **>(alloca(sizeof(char*)*count_args));
            {
                int upto = 0;
                argv_pass[upto++] = bin_path.data();
                argv_pass[upto++] = "--server";
                argv_pass[upto++] = "--maxmsg";
                argv_pass[upto++] = shm_size;
                argv_pass[upto++] = "--port";
                argv_pass[upto++] = port_str;
                argv_pass[upto++] = "--cert";
                argv_pass[upto++] = cert_path.data();
                argv_pass[upto++] = "--key";
                argv_pass[upto++] = key_path.data();
                argv_pass[upto++] = "--cntlfd";
                argv_pass[upto++] = "3";
                argv_pass[upto++] = "--maxcon";
                argv_pass[upto++] = max_con_str;
                argv_pass[upto++] = "--maxconip";
                argv_pass[upto++] = max_con_per_ip_str;
                for ( std::string_view& arg : argv )
                    argv_pass[upto++] = arg.data();
                argv_pass[upto] = NULL; 
            }

            pid = vfork();
            if (pid) {

                // --- PARENT

                close(fd[1]);
                
                int flags = fcntl(fd[0], F_GETFD, NULL);
                if (flags < 0)
                    HPWS_SERVER_ERROR(101, "could not get flags from unix domain socket");

                flags |= FD_CLOEXEC;
                if (fcntl(fd[0], F_SETFD, flags))
                    HPWS_SERVER_ERROR(102, "could notset flags for unix domain socket");

                // we will set a timeout and wait for the initial startup message from hpws server mode
                struct pollfd pfd;
                int ret;

                pfd.fd = fd[0];
                pfd.events = POLLIN;
                ret = poll(&pfd, 1, HPWS_LONG_TIMEOUT); // default= 1500 ms timeout

                // timeout or error
                if (ret < 1)
                    HPWS_SERVER_ERROR(1, "timeout waiting for hpws startup message");

                char buf[1024];
                int bytes_read = recv(fd[0], buf,sizeof(buf) - 1, 0); 
                if (bytes_read < 1)
                    HPWS_SERVER_ERROR(2, "nil message sent by hpws on startup");

                buf[bytes_read] = '\0';
                if (strncmp(buf, "startup", 7) != 0) {
                    fprintf(stderr, "startup message: `%.*s`\n", bytes_read, buf);
                    HPWS_SERVER_ERROR(3, "unexpected content in message sent by hpws on startup");
                }
                return server {
                    pid,
                    fd[0],
                    max_buffer_size
                };

            } else {
          
                // --- CHILD
                
                close(fd[0]);
                
                // dup fd[1] into fd 3
                dup2(fd[1], 3);
                close(fd[1]);
                    
                // we're assuming all fds above 3 will have close_exec flag
                execv(bin_path.data(), (char* const*)argv_pass);
                // we will send a nil message down the pipe to help the parent know somethings gone wrong
                char nil[1];
                nil[0] = 0;
                send(3, nil, 1, 0);
                exit(1); // execl failure as child will always result in exit here
            
            }
            
 
            server_error:;

                // NB: execution to here can only happen in parent process            
                // clean up any mess after error
                if (pid > 0) 
                    kill(pid, SIGKILL); /* RH TODO change this to SIGTERM and set a timeout? */
                    int status;
                    waitpid(pid, &status, 0 /* should we use WNOHANG? */);
                if (fd[0] > 0)
                    close(fd[0]);
                if (fd[1] > 0)
                    close(fd[1]);
                
                return error{error_code, std::string{error_msg}};
        }
    };
}


#endif

