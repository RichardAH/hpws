#include <variant>
    #include <vector>
#include "hpws.hpp"


int main() {

/*    
        static std::variant<server, error> create(
            std::string_view bin_path,
            uint32_t max_buffer_size,
            uint16_t port,
            uint32_t max_con,
            uint16_t max_con_per_ip,
            std::string_view cert_path,
            std::string_view key_path,
            std::vector<std::string_view>& argv //additional_arguments 
        ){
*/

    #define PRINT_HPWS_ERROR(obj)\
    {\
        if (std::holds_alternative<hpws::error>(obj)) {\
            hpws::error e = std::get<hpws::error>(obj);\
            printf("error code: %d -- error msg: %.*s\n", e.first, (int)(e.second.size()), e.second.data());\
        } else printf("asked to print an error but the object was not an error object\n");\
    }
    auto server = hpws::server::create ( "hpws", 16*1024*1024, 443, 512, 2, "cert.pem", "key.pem", {} );

    if ( std::holds_alternative<hpws::server>(server) ) {
        printf("we got a server\n");

        auto client = std::get<hpws::server>(server).accept();

        if (std::holds_alternative<hpws::client>(client)) {
            printf("a client connected\n");
        } else {
            PRINT_HPWS_ERROR(client);
        }


    } else if ( std::holds_alternative<hpws::error>(server) )  {
        printf("we got an error\n");
        PRINT_HPWS_ERROR(server);
    } else {
        printf("we got a donkey\n");
    }

    return 0;
}
