#include <iostream>
#include <sys/prctl.h>
#include "../hpws.hpp"

#define PRINT_HPWS_ERROR(obj)                                                                     \
    {                                                                                             \
        if (std::holds_alternative<hpws::error>(obj))                                             \
        {                                                                                         \
            hpws::error e = std::get<hpws::error>(obj);                                           \
            fprintf(stderr, "[echosvr] error code: %d -- error msg: %.*s\n",                      \
                    e.first, (int)(e.second.size()), e.second.data());                            \
        }                                                                                         \
        else                                                                                      \
            printf("[echosvr] asked to print an error but the object was not an error object\n"); \
    }

int echo_server();

int main(int argc, char **argv)
{
    // Become a sub-reaper so we can gracefully reap hpws child processes via hpws.hpp.
    // (Otherwise they will get reaped by OS init process and we'll end up with race conditions with gracefull kills)
    prctl(PR_SET_CHILD_SUBREAPER, 1);

    return echo_server();
}

int echo_server()
{
    auto server = hpws::server::create("hpws", 16 * 1024 * 1024, 8080, 512, 512, "cert.pem", "key.pem", {});

    if (std::holds_alternative<hpws::server>(server))
    {
        fprintf(stderr, "[echosvr] hpws echo server started\n");

        while (1)
        {
            auto accept_result = std::get<hpws::server>(server).accept();

            if (std::holds_alternative<hpws::client>(accept_result))
            {
                fprintf(stderr, "[echosvr] a client connected\n");
            }
            else
            {
                PRINT_HPWS_ERROR(accept_result);
                continue;
            }

            auto client = std::get<hpws::client>(std::move(accept_result));

            for (;;)
            {
                auto read_result = client.read();
                if (std::holds_alternative<hpws::error>(read_result))
                {
                    fprintf(stderr, "[echosvr] accept loop error\n");
                    PRINT_HPWS_ERROR(read_result);
                    break;
                }

                const std::string in_msg(std::get<std::string_view>(read_result));
                fprintf(stderr, "[echosvr] got message size: %d\n", (int)in_msg.size());
                client.ack(in_msg);

                // Reply with the same message we got.
                client.write(in_msg);
            }
        }
    }
    else if (std::holds_alternative<hpws::error>(server))
    {
        fprintf(stderr, "[echosvr] we got an error\n");
        PRINT_HPWS_ERROR(server);
    }
    else
    {
        fprintf(stderr, "[echosvr] we got a donkey\n");
    }

    return 0;
}
