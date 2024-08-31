#!/bin/bash

gcc  server.c ../src/*.c -I../include -I../test_msg_type -lpthread -lrt -o rpc_server
gcc client.c ../src/*.c -I../include -I../test_msg_type -lpthread -lrt -o rpc_client