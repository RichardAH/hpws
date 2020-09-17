#ifndef HPWS_INCLUDE
#define HPWS_INCLUDE
#include <optional>

namespace hpws {

    class server;

    class client {

    public:
        sockaddr_in6 client_endpoint;
        int control_line_fd;
        int buffer_out_fd[2];
        int buffer_in_fd[2];
        void* buffer_out[2];
        void* buffer_int[2];
        

        static client connect_ipv4_str ( char ip[15], int port )
        {


        }

        static client connect_ipv6 ( sockaddr_in6 endpoint )
        {

        }

        friend class server;
    }

    class server {

    public:
        int master_control_fd;  
        int server_pid;

        static std::optional<server> create_server(
            char* path_to_binary,
            char** arguments, // should be null terminated
            int& out_error_code,
            std::string& out_error_msg
        ){
            #define HPWS_SERVER_ERROR(code, msg)\
            {\
                out_error_code = code;\
                out_error_msg = std::string{msg};\
                goto error;\
            }
            
            int fd[2] = {-1, -1}; 
            int pid = -1;            

            if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fd))
                HPWS_SERVER_ERROR(100, "could not create unix domain socket pair");

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
                struct pollfd fd;
                int ret;

                fd.fd = fd[0];
                fd.events = POLLIN;
                ret = poll(&fd, 1, 1500); // 1500 ms timeout

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
                    .server_pid = pid
                };

            } else {
          
                // --- CHILD
                
                close(fd[0]);
                
                // dup fd[1] into fd 3
                dup2(fd[1], 3);
                close(fd[1]);
                    
                // we're assuming all fds above 3 will have close_exec flag
                execl(path_to_binary, argv);
                exit(1); // execl failure as child will always result in exit here
            
            }

 
            error:
                // NB: execution to here can only happen in parent process            
                // clean up any mess after error
                if (pid > 0) 
                    kill(pid, SIGKILL);
                if (fd[0] > 0)
                    close(fd[0]);
                if (fd[1] > 0)
                    close(fd[1]);
                return std::nullopt;
        }
    }
}


#endif

