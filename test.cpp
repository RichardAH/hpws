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

    auto server = hpws::server::create ( "hpws", 16*1024*1024, 443, 512, 2, "cert.pem", "key.pem", {} );

    if ( std::holds_alternative<hpws::server>(server) ) {
        printf("we got a server\n");
    } else if ( std::holds_alternative<hpws::error>(server) )  {
        printf("we got an error\n");
        hpws::error e = std::get<hpws::error>(server);
        printf("error code: %d -- error msg: %.*s\n", e.first, (int)(e.second.size()), e.second.data());
    } else {
        printf("we got a donkey\n");
    }

    return 0;
}
