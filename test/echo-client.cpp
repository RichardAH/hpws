#include <iostream>
#include <sys/prctl.h>
#include "../hpws.hpp"

constexpr const char *SERVER = "localhost";
constexpr uint16_t PORT = 9001;
constexpr const char *AGENT = "hpwsclient";

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
int get_case_count();
int echo_client(const uint32_t caseid);
int update_reports();

int main(int argc, char **argv)
{
    // Become a sub-reaper so we can gracefully reap hpws child processes via hpws.hpp.
    // (Otherwise they will get reaped by OS init process and we'll end up with race conditions with gracefull kills)
    prctl(PR_SET_CHILD_SUBREAPER, 1);

    int case_count = get_case_count();
    if (case_count == -1)
    {
        std::cout << "[echoclient] failed to get case count. Set to default count.\n";
        case_count = 519;
    }
    std::cout << "[echoclient] case count: " << case_count << "\n";

    // We need to repeatedly re-connect to the test server as it will disconnect us after each test case.
    uint32_t caseid = 1;
    while (caseid <= case_count)
    {
        echo_client(caseid++);
    }

    update_reports();
    return 0;
}

int get_case_count()
{
    const std::string path = "/getCaseCount";
    auto accept_result = hpws::client::connect("hpws", 16 * 1024 * 1024, SERVER, PORT, path, {});

    if (std::holds_alternative<hpws::client>(accept_result))
    {
        std::cout << "[echoclient] Connected to server to get case count\n";
    }
    else
    {
        PRINT_HPWS_ERROR(accept_result);
        return -1;
    }

    auto client = std::move(std::get<hpws::client>(accept_result));
    auto read_result = client.read();
    if (std::holds_alternative<hpws::error>(read_result))
    {
        PRINT_HPWS_ERROR(read_result);
        return -1;
    }

    std::string_view buffer = std::get<std::string_view>(read_result);
    const int case_count = std::stoi(std::string(buffer));
    client.ack(buffer);

    return case_count;
}

int echo_client(const uint32_t caseid)
{
    const std::string path = "/runCase?case=" + std::to_string(caseid) + "&agent=" + AGENT;
    auto accept_result = hpws::client::connect("hpws", 16 * 1024 * 1024, SERVER, PORT, path, {});

    if (std::holds_alternative<hpws::client>(accept_result))
    {
        std::cout << "[echoclient] Connected to server (test case: " << caseid << ")\n";
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
            return -1;
        }

        std::string_view buffer = std::get<std::string_view>(read_result);

        const std::string in_msg(buffer);
        fprintf(stderr, "[echoclient] got message size: %d\n", (int)in_msg.size());
        client.ack(buffer);

        // Reply with the same message we got.
        client.write(in_msg);
    }

    return 0;
}

int update_reports()
{
    const std::string path = std::string("/updateReports?agent=") + AGENT;
    auto accept_result = hpws::client::connect("hpws", 16 * 1024 * 1024, SERVER, PORT, path, {});

    if (std::holds_alternative<hpws::client>(accept_result))
    {
        std::cout << "[echoclient] Updating reports...\n";
    }
    else
    {
        PRINT_HPWS_ERROR(accept_result);
        return -1;
    }

    auto client = std::move(std::get<hpws::client>(accept_result));
    client.read(); // Wait until connection close.

    std::cout << "[echoclient] Reports updated";
    return 0;
}
