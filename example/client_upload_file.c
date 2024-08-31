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
#include <sys/stat.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "test_msg_type.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    int32_t task_id;
    char file_name[64];
    int32_t file_size;
} create_upload_file_task_req;

typedef struct {
    int32_t task_id;
    int32_t code;
} create_upload_file_task_resp;

struct upload_file_req {
    int32_t task_id;
    int32_t is_final_packet;
    int32_t data_len;
    uint8_t data[];
} __attribute__((packed));

typedef struct {
    int32_t task_id;
    int32_t code;
} upload_file_resp;

FILE *fp = NULL;
int file_size = 0;
rpc_client_t *cli;
int state = 0;

proc_result_t *on_create_upload_file_resp(void *ctx, void *payload, uint16_t payload_size)
{
    printf("receive resp\n");
    create_upload_file_task_resp *resp = (create_upload_file_task_resp *)payload;
    
    int code = ntohl(resp->code);
    if (code != 0) {
        printf("create upload file task failed\n");
        return NULL;
    }

    int length = sizeof(struct upload_file_req) + 1024 * 16;
    struct upload_file_req *req = malloc(length);
    memset(req, 0, length);

    int nread = fread(req->data, 1, 1024 * 16, fp);
    printf("read %d bytes\n", nread);
    if (nread == 0) {
        printf("upload file done\n");
        fclose(fp);
        state = 1;
        return NULL;
    }
    if (nread < 1024 * 16) {
        req->is_final_packet = htonl(1);
        length = sizeof(struct upload_file_req) + nread;
        printf("upload file done\n");
        fclose(fp);
        state = 1;
    } else {
        req->is_final_packet = htonl(0);
    }
    
    req->task_id = resp->task_id;
    req->data_len = htonl(nread);

    send_msg(cli, RPC_SYS_UPLOAD_FILE_REQ, req, length);

    return NULL;
}

proc_result_t *on_upload_file_resp(void *ctx, void *payload, uint16_t payload_size)
{
    if (state == 1) {
        exit(0);
    }
    printf("receive resp\n");
    upload_file_resp *resp = (upload_file_resp *)payload;
    
    int code = ntohl(resp->code);
    if (code != 0) {
        printf("upload file return failed\n");
        return NULL;
    }

    int length = sizeof(struct upload_file_req) + 1024 * 16;
    struct upload_file_req *req = malloc(length);
    memset(req, 0, length);

    int nread = fread(req->data, 1, 1024 * 16, fp);
    printf("read %d bytes\n", nread);
    if (nread <= 0) {
        printf("upload file done\n");
        fclose(fp);
        state = 1;
        return NULL;
    }
    if (nread < 1024 * 16) {
        req->is_final_packet = htonl(1);
        length = sizeof(struct upload_file_req) + nread;
        printf("upload file done\n");
        fclose(fp);
        state = 1;
    } else {
        req->is_final_packet = htonl(0);
    }
    
    req->task_id = resp->task_id;
    req->data_len = htonl(nread);

    send_msg(cli, RPC_SYS_UPLOAD_FILE_REQ, req, length);

    return NULL;
}

msg_handler_t create_upload_file_task_resp_hndl = {
    .name = "create_upload_file_task_resp",
    .in_check_func = fix_length_payload_check,
    .in_payload_size = sizeof(create_upload_file_task_resp),
    .in_msg_type = RPC_SYS_CREATE_UPLOAD_FILE_TASK_RESP,
    .proc_func = on_create_upload_file_resp,
    .free_func = NULL,
};

msg_handler_t upload_file_hndl = {
    .name = "fw_upgrade_resp_hndl",
    .in_check_func = fix_length_payload_check,
    .in_payload_size = sizeof(upload_file_resp),
    .in_msg_type = RPC_SYS_UPLOAD_FILE_RESP,
    .proc_func = on_upload_file_resp,
    .free_func = NULL,
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
    cli = new_rpc_client("172.20.0.100", 9000);
    if (cli == NULL) {
        printf("new client failed\n");
        return -1;
    }
    register_msg_handler(cli, &create_upload_file_task_resp_hndl);
    register_msg_handler(cli, &upload_file_hndl);
    rpc_client_set_disconnect_cb(cli, on_disconnect);
    rpc_client_set_connect_cb(cli, on_connect);
   // rpc_client_enable_keepalive(cli);
    if (start_rpc_client(cli) < 0) {
        printf("start rpc client failed\n");
        return -1;
    }

    char *filename = argv[1];
    fp = fopen(filename, "rb");
    struct stat st;
    stat(filename, &st);
    
    create_upload_file_task_req req;
    memset(&req, 0, sizeof(req));
    req.task_id = htonl(123);
    req.file_size = htonl(st.st_size);
    strncpy(req.file_name, filename, sizeof(req.file_name));
    printf("file size:%d\n", st.st_size);
    send_msg(cli, RPC_SYS_CREATE_UPLOAD_FILE_TASK_REQ, &req, sizeof(req));
    while (1) {
        //send_msg(cli, RPC_SYS_TEST_REQ, &req, sizeof(req));
        sleep(5);
    }
    fclose(fp);
}

