#include <signal.h>
#include <sys/wait.h>
#include <sys/resource.h>

#include <variant>
    #include <vector>
#include "hpws.hpp"


    #define PRINT_HPWS_ERROR(obj)\
    {\
        if (std::holds_alternative<hpws::error>(obj)) {\
            hpws::error e = std::get<hpws::error>(obj);\
            fprintf(stderr, "[TEST.CPP] error code: %d -- error msg: %.*s\n",\
                    e.first, (int)(e.second.size()), e.second.data());\
        } else printf("asked to print an error but the object was not an error object\n");\
    }

int example_server();
int example_client();
void proc_exit(int x)
{
		int wstat;
		pid_t pid;

		while (1) {
			pid = wait3 (&wstat, WNOHANG, (struct rusage *)NULL );
			if (pid == 0)
				return;
			else if (pid == -1)
				return;
			else
				fprintf (stderr, "[TEST.CPP] Child exit - Return code: %d\n", wstat);
		}
}

int main(int argc, char** argv) {
    signal (SIGCHLD, proc_exit);

    if (argc > 1 && argv[1][0] == 'c')
        example_client();
    else
        example_server();
}

int example_client() {
    auto accept_result = hpws::client::connect ( "hpws", 16*1024*1024, "test.evernode.org", 443, "/", {} );
    
    if (std::holds_alternative<hpws::client>(accept_result)) {
        printf("[TEST.CPP] a client connected\n");
    } else {
        PRINT_HPWS_ERROR(accept_result);
    }

    auto client = std::move(std::get<hpws::client>(accept_result));


    {
        int msgcounter = 0;
        fprintf(stderr, "[TEST.CPP] sending message\n");
        client.write("test message!\n");
        for(;;) {
            auto read_result = client.read();
            if ( std::holds_alternative<hpws::error>(read_result) ) {
                PRINT_HPWS_ERROR(read_result);
                return 1;
               // break;
            }

            std::string_view s = std::get<std::string_view>(read_result);
            
            fprintf(stderr, "[TEST.CPP] got message from hpws: `%.*s`\n", s.size(), s.data());
            //fprintf(stderr, "[TEST.CPP] got message size: %d\n", s.size());
            fprintf(stderr, "[TEST.CPP] buf contained: `");
            for (int i = 0; i < s.size(); ++i)
               putc(s[i], stderr);
            fprintf(stderr,"`\n");           

            client.ack(s);    
            char out[1024];
            sprintf(out, "message from client: %d\n", ++msgcounter);
            client.write(out);

        }
    }

}


int example_server() {
    auto server = hpws::server::create ( "hpws", 16*1024*1024, 443, 512, 2, "cert.pem", "key.pem", {} );

    if ( std::holds_alternative<hpws::server>(server) ) {
        fprintf(stderr, "[TEST.CPP] we got a server\n");

        while (1) {
        auto accept_result = std::get<hpws::server>(server).accept();

        if (std::holds_alternative<hpws::client>(accept_result)) {
            fprintf(stderr, "[TEST.CPP] a client connected\n");
        } else {
            PRINT_HPWS_ERROR(accept_result);
        }

        auto client = std::get<hpws::client>(std::move(accept_result));
        int counter = 0;
        for(;;) {
            auto read_result = client.read();
            if ( std::holds_alternative<hpws::error>(read_result) ) {
                PRINT_HPWS_ERROR(read_result);
                //return 1;
                break;
            }

            std::string_view s = std::get<std::string_view>(read_result);
            
            //printf("got message from hpws: `%.*s`\n", s.size(), s.data());
            fprintf(stderr, "[TEST.CPP] %.*s", s.size(), s.data());
            fprintf(stderr, "[TEST.CPP] got message size: %d\n", s.size());
            fprintf(stderr, "[TEST.CPP] contained: `");
            for (int i = 0; i < s.size(); ++i)
                putc(s[i], stderr);
            fprintf(stderr,"`\n");           
 
            client.ack(s);    

            char out[1024];
            sprintf(out, "message from server: %d\n", ++counter);
            client.write(out);

        }
        }

    } else if ( std::holds_alternative<hpws::error>(server) )  {
        fprintf(stderr, "[TEST.CPP] we got an error\n");
        PRINT_HPWS_ERROR(server);
    } else {
        fprintf(stderr, "[TEST.CPP] we got a donkey\n");
    }

    return 0;
}
