#include <variant>
    #include <vector>
#include "hpws.hpp"


int main() {

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

        while (1) {
        auto accept_result = std::get<hpws::server>(server).accept();

        if (std::holds_alternative<hpws::client>(accept_result)) {
            printf("a client connected\n");
        } else {
            PRINT_HPWS_ERROR(accept_result);
        }

        auto client = std::get<hpws::client>(std::move(accept_result));

        for(;;) {
            auto read_result = client.read();
            if ( std::holds_alternative<hpws::error>(read_result) ) {
                PRINT_HPWS_ERROR(read_result);
                //return 1;
                break;
            }

            std::string_view s = std::get<std::string_view>(read_result);
            
            //printf("got message from hpws: `%.*s`\n", s.size(), s.data());
            fprintf(stderr, "%.*s", s.size(), s.data());
            printf("got message size: %d\n", s.size());
            //fprintf(stderr, "buf contained: `");
            //for (int i = 0; i < s.size(); ++i)
            //    putc(s[i], stderr);
            //fprintf(stderr,"`\n");           
 
            client.ack(s);    
        }
        }

    } else if ( std::holds_alternative<hpws::error>(server) )  {
        printf("we got an error\n");
        PRINT_HPWS_ERROR(server);
    } else {
        printf("we got a donkey\n");
    }

    return 0;
}
