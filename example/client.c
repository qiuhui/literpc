/*
 * File: client.c
 * File Created: Tuesday, 18th June 2024 11:22:07 am
 * Author: qiuhui (qiuhui@leelen.com)
 * -----
 * Last Modified: Tuesday, 18th June 2024 11:22:09 am
 * Modified By: qiuhui (qiuhui@leelen.com>)
 * -----
 * Copyright - 2024 leelen, leelen
 */

#include "rpc_client.h"
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "test_msg_type.h"

typedef struct {
    int32_t sensor_id;
}request_iframe_req;

typedef  struct {
    int32_t status;
}request_iframe_resp;

proc_result_t *hndl(void *ctx, void *payload, uint16_t payload_size)
{
    printf("receive resp\n");
    request_iframe_resp *resp = (request_iframe_resp *)payload;
    printf("status:%d\n", ntohl(resp->status));
    return NULL;
}


msg_handler_t test_hndl = {
    .name = "test",
    .in_check_func = NULL,
    .in_payload_size = 0,
    .in_msg_type = RPC_SYS_TEST_RESP,
    .proc_func = hndl,
};

void on_disconnect(const void *ctx)
{
    printf("disconnect\n");
}

void on_connect(const void *ctx)
{
    printf("connect\n");
}
int main(int argc, char *argv[])
{
    rpc_client_t *cli = new_rpc_client("127.0.0.1", 9900);
    if (cli == NULL) {
        printf("new client failed\n");
        return -1;
    }
    register_msg_handler(cli, &test_hndl);
    rpc_client_set_disconnect_cb(cli, on_disconnect);
    rpc_client_set_connect_cb(cli, on_connect);
    rpc_client_enable_keepalive(cli);
    if (start_rpc_client(cli) < 0) {
        printf("start rpc client failed\n");
        return -1;
    }
    request_iframe_req req;
    req.sensor_id = htonl(1);
    
    while (1) {
        //send_msg(cli, RPC_SYS_TEST_REQ, &req, sizeof(req));
        sleep(5);
    }
}