all: hpws test 

hpws: hpws.c
	gcc hpws.c -o hpws -g -lcrypto -lssl

test: test.cpp hpws.hpp
	g++ test.cpp -o test -g -lcrypto -lssl --std=c++17

test_client: test_client.cpp hpws.hpp
	g++ test_client.cpp -o test_client -g -lcrypto -lssl --std=c++17
