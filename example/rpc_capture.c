#include "rpc_client.h"
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "test_msg_type.h"
#include <stdlib.h>
#include <string.h>
#include "rpc_capture.h"
#include <pthread.h>

typedef struct {
    int32_t request_id;
    int32_t image_format;
    int32_t timeout;
}request_pd_task_req;

typedef struct{
    int32_t request_id;
    int32_t status;
}request_pd_task_resp;

typedef  struct {
    int32_t request_id;
    int32_t result;
    int32_t image_format;
    int32_t image_width;
    int32_t image_height;
    int32_t person_cnt;
    char coordinates[];
}__attribute__((packed))request_pd_result_req;

typedef  struct {
    int32_t request_id;
    int32_t status;
}request_pd_result_resp;

typedef  struct {
    int32_t request_id;
    int32_t packet_index;
    int32_t is_final_packet;
    char image_data[];
}__attribute__((packed)) request_pd_photo_req;

typedef  struct {
    int32_t request_id;
    int32_t ack_packet_index;
}request_pd_photo_resp;

volatile int rpc_proc_statu = 0;
static pthread_t capture_th;
static pthread_mutex_t mutex;
static int request_id = 0;

static rpc_client_t *cap_cli = NULL;
static video_get_data_cb get_data_cb = NULL;
static void* callback_args = NULL;
static capture_result_t* cr = NULL;

proc_result_t *pd_task_resp(void *ctx, void *payload, uint16_t payload_size)
{
    request_pd_task_resp *resp = (request_pd_task_resp *)payload;
    printf("receive pd_task_resp request id:%d\n",resp->request_id);
    printf("paylod_size:%d\n",payload_size);
    printf("status :%d\n", ntohl(resp->status));
    return NULL;
}

proc_result_t *pd_result_req(void *ctx, void *payload, uint16_t payload_size)
{
    request_pd_result_req *req = (request_pd_result_req *)payload;
    printf("paylod_size:%d\n",payload_size);
    printf("receive pd_result_req  request id:%d\n",req->request_id);
    printf("result:%d\n", ntohl(req->result));

    proc_result_t *output = malloc(sizeof(proc_result_t));
    request_pd_result_resp *resp = malloc(sizeof(request_pd_result_resp));
    resp->request_id = ntohl(request_id);

    if(req->result)
    {
        resp->status = ntohl(1);
    }else{
        resp->status = ntohl(0);
    }

    output->priv_data = NULL;
    output->payload = (void*)resp;
    output->payload_size = sizeof(request_pd_result_resp);
    printf("pd_result_resp:rpc_proc_statu: %d\n",rpc_proc_statu);
    return output;
}

proc_result_t *pd_photo_req(void *ctx, void *payload, uint16_t payload_size)
{
    
    printf("paylod_size:%d\n",payload_size);
    request_pd_photo_req *req = (request_pd_photo_req *)payload;
    printf("receive pd_photo_req request id:%d\n",req->request_id);
    printf("\n");
    printf("packet_index: %d\n",ntohl(req->packet_index));
    printf("if final: %d\n",ntohl(req->is_final_packet));
    proc_result_t *output = malloc(sizeof(proc_result_t));
    request_pd_photo_resp *resp = malloc(sizeof(request_pd_photo_resp));
    resp->ack_packet_index = ntohl(req->packet_index);
    resp->request_id = ntohl(request_id);
    output->priv_data = NULL;
    output->payload = (void*)resp;
    output->payload_size = sizeof(request_pd_photo_resp);
        
    return output;
}

msg_handler_t pd_task_resp_hndl = {
    .name = "pd_task_resp",
    .in_check_func = NULL,
    .in_payload_size = 0,
    .in_msg_type = RPC_VIDEO_CREATE_PEDESTRIAN_DETECT_TASK_RESP,
    .proc_func = pd_task_resp,
};

msg_handler_t pd_result_req_hndl = {
    .name = "pd_result_req",
    .in_check_func = NULL,
    // .in_payload_size = sizeof(request_pd_result_req),
    .in_msg_type = RPC_VIDEO_PEDESTRIAN_DETECT_NOTIFY_REQ,
    .out_msg_type = RPC_VIDEO_PEDESTRIAN_DETECT_NOTIFY_RESP,
    .proc_func = pd_result_req,
};

msg_handler_t pd_photo_req_hndl = {
    .name = "pd_photo_req",
    .in_check_func = NULL,
    // .in_payload_size = sizeof(request_pd_photo_req),
    .in_msg_type = RPC_VIDEO_PEDESTRIAN_DETECT_IMAGE_SEND_REQ,
    .out_msg_type = RPC_VIDEO_PEDESTRIAN_DETECT_IMAGE_SEND_RESP,
    .proc_func = pd_photo_req,
};

void on_disconnect(const void *ctx)
{
    printf("=====disconnect========\n");
}

void on_connect(const void *ctx)
{
    printf("======connect=======\n");
}

int main(int argc, char *argv[])
{
    cap_cli = new_rpc_client("172.20.0.100", 9000);
    if (cap_cli == NULL) {
        printf("new client failed\n");
        return -1;
    }
    register_msg_handler(cap_cli, &pd_task_resp_hndl);
    register_msg_handler(cap_cli, &pd_result_req_hndl);
    register_msg_handler(cap_cli, &pd_photo_req_hndl); 
    rpc_client_set_disconnect_cb(cap_cli, on_disconnect);
    rpc_client_set_connect_cb(cap_cli, on_connect);
    // rpc_client_enable_keepalive(cli);
    if (start_rpc_client(cap_cli) < 0) {
        printf("start rpc client failed\n");
        return -1;
    }else{
         printf("======start rpc client success==========\n");
        while (1) {
            request_pd_task_req req = {0};
            req.request_id = htonl(0);
            req.image_format = htonl(1);
            req.timeout = htonl(2000);
            printf("sned msg\n");
            send_msg(cap_cli, RPC_VIDEO_CREATE_PEDESTRIAN_DETECT_TASK_REQ, &req, sizeof(req));
            sleep(3);
        }
    }
    return 1;
}



