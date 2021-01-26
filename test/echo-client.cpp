#include <iostream>
#include <sys/prctl.h>
#include "../hpws.hpp"

#define PRINT_HPWS_ERROR(obj)                                                                        \
    {                                                                                                \
        if (std::holds_alternative<hpws::error>(obj))                                                \
        {                                                                                            \
            hpws::error e = std::get<hpws::error>(obj);                                              \
            fprintf(stderr, "[echoclient] error code: %d -- error msg: %.*s\n",                      \
                    e.first, (int)(e.second.size()), e.second.data());                               \
        }                                                                                            \
        else                                                                                         \
            printf("[echoclient] asked to print an error but the object was not an error object\n"); \
    }

int echo_client();

int main(int argc, char **argv)
{
    // Become a sub-reaper so we can gracefully reap hpws child processes via hpws.hpp.
    // (Otherwise they will get reaped by OS init process and we'll end up with race conditions with gracefull kills)
    prctl(PR_SET_CHILD_SUBREAPER, 1);

    // We need to repeatedly re-connect to the test server as it will disconnect us after each test case.
    while (echo_client() != -1)
        ;
}

int echo_client()
{
    auto accept_result = hpws::client::connect("hpws", 16 * 1024 * 1024, "localhost", 9001, "/", {});

    if (std::holds_alternative<hpws::client>(accept_result))
    {
        printf("[echoclient] Connected to server\n");
    }
    else
    {
        PRINT_HPWS_ERROR(accept_result);
        return -1;
    }

    auto client = std::move(std::get<hpws::client>(accept_result));

    while (1)
    {
        auto read_result = client.read();
        if (std::holds_alternative<hpws::error>(read_result))
        {
            PRINT_HPWS_ERROR(read_result);
            return 1;
        }

        std::string_view buffer = std::get<std::string_view>(read_result);

        const std::string in_msg(buffer);
        fprintf(stderr, "[echoclient] got message size: %d\n", (int)in_msg.size());
        client.ack(buffer);

        // Reply with the same message we got.
        client.write(in_msg);
    }
}
