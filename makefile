all: hpws test 

hpws: hpws.c
	gcc hpws.c -o hpws -g -lcrypto -lssl

example: example.cpp hpws.hpp
	g++ example.cpp -o example -g -lcrypto -lssl --std=c++17

test: test/echo-server.cpp hpws.hpp
	g++ test/echo-server.cpp -o echo-server -g -lcrypto -lssl --std=c++17
