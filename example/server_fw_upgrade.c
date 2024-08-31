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


#include <assert.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "rpc_server.h"
#include "test_msg_type.h"

typedef struct {
    int32_t sensor_id;
}request_iframe_req;

typedef  struct {
    int32_t status;
}request_iframe_resp;

proc_result_t output;
request_iframe_resp resp;
static proc_result_t *do_request_iframe(void *ctx, void *payload, uint16_t payload_size)
{
    request_iframe_req *req = (request_iframe_req *)payload;
    int32_t chn = ntohl(req->sensor_id);
    int32_t ret, ret1, ret2;

    ret = 5;

    resp.status = htonl(ret);
    output.payload = &resp;
    output.payload_size = sizeof(request_iframe_resp);

    return &output;
}

rpc_service video_svc = {
    .name = "test_service",
    .id = 0x01,
};

static msg_handler_t hndls[] = {
    { 
        .name = "test_handler",
        .in_msg_type = RPC_SYS_TEST_REQ,
        .in_payload_size = sizeof(request_iframe_resp), 
        .in_check_func = fix_length_payload_check,
        .out_msg_type = RPC_SYS_TEST_RESP,
        .proc_func = do_request_iframe,
        .free_func = NULL,
    },
};
__attribute__((constructor)) static void register_service() {
    video_svc.hndls = hashmap_new(sizeof(msg_handler_t), 0, 0, 0, rpc_hash, rpc_compare, NULL, NULL);
    int i;
    for (i = 0; i < sizeof(hndls) / sizeof(hndls[0]); i++) {
        assert(hndls[i].proc_func);
        assert(hndls[i].in_msg_type >> 8 == video_svc.id);
        hashmap_set(video_svc.hndls, &hndls[i]);
    }
    assert(register_rpc_service(&video_svc) == 0);
}

void on_disconnect(const void *ctx)
{
    rpc_event_loop *loop = (rpc_event_loop *)ctx;
    printf("client %s:%d disconnect\n", loop->peer_ip, loop->peer_port);
}

void on_connect(const void *ctx)
{
    rpc_event_loop *loop = (rpc_event_loop *)ctx;
    printf("client %s:%d connect\n", loop->peer_ip, loop->peer_port);
}
int main(int argc, char *argv[])
{
    rpc_server_set_work_threads(1);
    rpc_server_set_max_connections(1);
    rpc_server_set_disconnect_cb(on_disconnect);
    rpc_server_set_connect_cb(on_connect);
    rpc_server_enable_keepalive();
    rpc_server_start(9900);

    while (1) {
        sleep(1);
    }
    return 0;
}