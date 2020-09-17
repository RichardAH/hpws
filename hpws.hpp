#ifndef HPWS_INCLUDE
#define HPWS_INCLUDE
#include <variant>
#include <optional>
#include <alloca.h>

namespace hpws {

    using error = std::pair<int, std::string>;

    // used when waiting for messages that should already be on the pipe
    #define HPWS_SMALL_TIMEOUT 1
    // used when waiting for server process to spawn
    #define HPWS_LONG_TIMEOUT 1500 

    class server;

    class client {

    private: 
        std::optional<server&> server; // if this client was created from an accept this is set
        std::optional<int> child_pid;  // if this client was created by a connect this is set
        int max_buffer_size; // this value can't be changed once it's established between the processes

        bool moved = false;
    public:


        sockaddr_in6 endpoint;
        int control_line_fd;
        int buffer_fd[4]; // 0 1 - in buffers, 2 3 - out buffers
        void* buffer[4];
        // No copy constructor
        client(const client&) = delete;

        // only a move constructor
        client ( client&& old ) : 
            server(old.server), 
            child_pid(old.child_pid), 
            max_buffer_size(old.max_buffer_size)  
        {
            old.moved = true;
        }

        ~client {
            if (!moved) {
                if (server.has_value())
                    server.child_destroyed(this);                

                // RH TODO ensure this pid terminates by following up with a SIGKILL
                if (child_pid.has_value()) 
                    kill(pid, SIGTERM);
               
                for (int i = 0; i < 4; ++i) {
                    munmap(buffer[i], max_buffer_size);
                    close(buffer_fd[i]);
                }
                
                close(control_line_fd);
            }
        } 
/*
        static client connect_ipv4_str ( char ip[15], int port )
        {


        }

        static client connect_ipv6 ( sockaddr_in6 endpoint )
        {

        }
*/
        friend class server;
    }

    class server {

        int max_buffer_size;
    public:
        int master_control_fd;  
        int server_pid;
        

        std::variant<client, error> accept()
        {
            #define HPWS_ACCEPT_ERROR(code,msg)\
            {return error{code, std::string{msg}};}
            int child_fd = -1;
            {
                struct msghdr child_msg = { 0 };
                memset(&child_msg, 0, sizeof(child_msg));
                char cmsgbuf[CMSG_SPACE(sizeof(int))];
                child_msg.msg_control = cmsgbuf;
                child_msg.msg_controllen = sizeof(cmsgbuf);

                int bytes_read = 
                    recvmsg(this->master_control_fd, &child_msg, 0);
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
                HPWS_SERVER_ERROR(202, "timeout waiting for hpws accept child message");

            // first thing we'll receive is the IP address structure of the client
            
            unsigned char buf[sizeof(sockaddr_in6)];
            int bytes_read =
                recv(child_fd, buf, sizeof(buf), 0);            

            if (bytes_read < sizeof(sockaddr_in6))
                HPWS_ACCEPT_ERROR(202, "received message on master control line was not sizeof(sockaddr_in6)");

            // second thing we will receive is the four fds for the buffers
            int buffer_fd[4]  =  { -1, -1, -1, -1 };
            void* mapping[4];
            {
                struct msghdr child_msg = { 0 };
                memset(&child_msg, 0, sizeof(child_msg));
                char cmsgbuf[CMSG_SPACE(sizeof(int))];
                child_msg.msg_control = cmsgbuf;
                child_msg.msg_controllen = sizeof(cmsgbuf);

                int bytes_read = 
                    recvmsg(child_fd, &child_msg, 0);
                struct cmsghdr *cmsg = CMSG_FIRSTHDR(&child_msg);
                if (cmsg == NULL || cmsg -> cmsg_type != SCM_RIGHTS)
                    HPWS_ACCEPT_ERROR(203, "non-scm_rights message sent on accept child control line");
                memcpy(&buffer_fd, CMSG_DATA(cmsg), sizeof(buffer_fd));
                for (int i = 0; i < 4; ++i) {
                    if (buffer_fd[i] < 0)
                        HPWS_ACCEPT_ERROR(203, "child accept scm_rights a passed buffer fd was negative"); 
                    mapping[i] = 
                        mmap( 0, max_buffer_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0 );
                    if (mapping[i] == (void*)(-1))
                        HPWS_ACCEPT_ERROR(204, "could not mmap scm_rights passed buffer fd");
                }
            }

            return {
                .endpoint = *(reinterpret_cast<sockaddr_in6*>(buf)),
                .control_line_fd = child_fd,
                .buffer_fd = { buffer_fd[0], buffer_fd[1], buffer_fd[2], buffer_fd[3] },
                .buffer = { mapping[0], mapping[1], mapping[2], mapping[3] },
                .max_buffer_size = this->max_buffer_size
            };
    
        }
    
        static std::variant<server, error> create_server(
            std::string_view binary_path,
            uint32_t max_buffer_size,
            uint16_t port,
            std::string_view cert_path,
            std::string_view key_path,
            std::vector<std::string_view> additional_arguments, 
        ){

            int error_code = -1;
            char* error_msg = NULL;
            #define HPWS_SERVER_ERROR(code, msg)\
                error_code = code;\
                error_msg = msg;\
                goto server_error;\
            }
            
            int fd[2] = {-1, -1}; 
            int pid = -1;            

            if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fd))
                HPWS_SERVER_ERROR(100, "could not create unix domain socket pair");

            // construct the arguments

            /*      ./bin
                    --server
                    --max_frame_size
                    <max_frame_size>
                    --port
                    <port>
                    --cert
                    <cert>
                    --key
                    <key>
                                
                    ...args
                    NULL
            */


            char shm_size[32];
            if (snprintf(shm_size, 32, "%d", max_buffer_size) <= 0)
                HPWS_SERVER_ERROR(90, "couldn't write shm size to string");
 
            char port_str[6];
            if (snprintf(port_str, 6, "%d", port) <= 0)
                HPWS_SERVER_ERROR(91, "couldn't write port to string");

            int count_args = 11;
            for (; argv[count_args]; ++count_args);

            char** argv_pass =
                reinterpret_cast<char**>(alloca(sizeof(char*)*count_args));

            int upto = 0;
            argv_pass[upto++] = path_to_binary;
            argv_pass[upto++] = "--server";
            argv_pass[upto++] = "--max_frame_size";
            argv_pass[upto++] = shm_size;
            argv_pass[upto++] = "--port";
            argv_pass[upto++] = port_str;
            argv_pass[upto++] = "--cert";
            argv_pass[upto++] = cert.data();
            argv_pass[upto++] = "--key";
            argv_pass[upto++] = key.data();
            
            for (int i = 0; i < count_args - 3; ++i)
                argv_pass[upto++] = argv[i];
            argv_pass[upto] = NULL; 

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
                if (strcmp(buf, "started") !== 0)
                    HPWS_SERVER_ERROR(3, "unexpected content in message sent by hpws on startup");

                return {
                    .master_control_fd = fd[0],
                    .server_pid = pid,
                    .max_buffer_size = max_buffer_size
                };

            } else {
          
                // --- CHILD
                
                close(fd[0]);
                
                // dup fd[1] into fd 3
                dup2(fd[1], 3);
                close(fd[1]);
                    
                // we're assuming all fds above 3 will have close_exec flag
                execl(path_to_binary, argv_pass);
                exit(1); // execl failure as child will always result in exit here
            
            }

 
            server_error:
                // NB: execution to here can only happen in parent process            
                // clean up any mess after error
                if (pid > 0) 
                    kill(pid, SIGKILL); /* RH TODO change this to SIGTERM and set a timeout? */
                    int status;
                    waitpid(pid, &status, 0 /* WNOHANG */);
                if (fd[0] > 0)
                    close(fd[0]);
                if (fd[1] > 0)
                    close(fd[1]);
                
                return error{error_code, std::string{error_msg}};
        }
    }
}


#endif

