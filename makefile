all: hpws echo-server echo-client

hpws: hpws.c
	gcc hpws.c -o hpws -g -lcrypto -lssl

example: example.cpp hpws.hpp
	g++ example.cpp -o example -g -lcrypto -lssl --std=c++17

echo-server: test/echo-server.cpp hpws.hpp
	g++ test/echo-server.cpp -o echo-server -g -lcrypto -lssl --std=c++17

echo-client: test/echo-client.cpp hpws.hpp
	g++ test/echo-client.cpp -o echo-client -g -lcrypto -lssl --std=c++17