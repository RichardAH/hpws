#!/bin/bash

make hpws test
if [ -f key.pem -a -f cert.pem ]; then
    echo "tls keys exist."
else
    rm key.pem cert.pem > /dev/null 2>&1
    openssl req -newkey rsa:2048 -new -nodes -x509 -days 3650 -keyout key.pem -out cert.pem -subj "/C=AU/ST=ACT/L=AU/O=hpws/CN=hpws"
fi
./echo-server