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
//#include <openssl/md5.h>
#include "md5.h"

typedef struct {
    int32_t sensor_id;
}request_iframe_req;

typedef  struct {
    int32_t status;
}request_iframe_resp;

typedef struct {
    int32_t request_id;
    char fw_version[32];
    int32_t fw_size;
    char md5_sum[32];
} fw_upgrade_notify;

typedef struct {
    int32_t request_id;
    int32_t status;
} fw_upgrade_notify_resp;

typedef struct {
    int32_t request_id;
    int32_t offset;
    int32_t length;
} pull_packet_req;

struct pull_packet_resp {
    int32_t request_id;
    int32_t offset;
    int32_t length;
    int32_t size;
    uint8_t data[];
} __attribute__((packed));

FILE *fp = NULL;
int file_size = 0;


#if  1
// 将二进制数据转换为十六进制字符串
void bin2hex(unsigned char *binary, char *hex) {
    static const char *hex_chars = "0123456789abcdef";
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        unsigned char current_byte = binary[i];
        hex[i * 2] = hex_chars[current_byte >> 4];
        hex[i * 2 + 1] = hex_chars[current_byte & 0xf];
    }
    hex[MD5_DIGEST_LENGTH * 2] = '\0'; // 添加字符串结尾
}
#endif
proc_result_t *hndl(void *ctx, void *payload, uint16_t payload_size)
{
    printf("receive resp\n");
    request_iframe_resp *resp = (request_iframe_resp *)payload;
    printf("status:%d\n", ntohl(resp->status));
    return NULL;
}

proc_result_t *on_pull_packet(void *ctx, void *payload, uint16_t payload_size)
{
    printf("receive resp\n");
    pull_packet_req *req = (pull_packet_req *)payload;
    int offset, length;

    offset = ntohl(req->offset);
    length = ntohl(req->length);
    printf("offset:%d, length:%d\n", offset, length);
    //fseek(fp, offset, SEEK_SET);
    int read_length = length;
    if (offset + length > file_size) {
        read_length = file_size - offset;
    }
    char *data = malloc(read_length);
    int nread = fread(data, 1, read_length, fp);
    printf("read_length:%d, nread:%d\n", read_length, nread);
    struct pull_packet_resp *resp = malloc(sizeof(struct pull_packet_resp) + nread);
    resp->request_id = req->request_id;
    resp->offset = req->offset;
    resp->length = req->length;
    resp->size = htonl(nread);
    memcpy(resp->data, data, nread);

    proc_result_t *output = malloc(sizeof(proc_result_t));
    output->priv_data = NULL;
    output->payload = (void *)resp;
    output->payload_size = sizeof(struct pull_packet_resp) + nread;

    free(data);
    return output;
}

msg_handler_t test_hndl = {
    .name = "test",
    .in_check_func = NULL,
    .in_payload_size = 0,
    .in_msg_type = RPC_SYS_TEST_RESP,
    .proc_func = hndl,
};

msg_handler_t pull_packet_hndl = {
    .name = "pull_packet_hndl",
    .in_check_func = fix_length_payload_check,
    .in_payload_size = sizeof(pull_packet_req),
    .in_msg_type = RPC_SYS_PULL_FIRMWARE_PACKET_REQ,
    .proc_func = on_pull_packet,
    .out_msg_type = RPC_SYS_PULL_FIRMWARE_PACKET_RESP,
    .free_func = default_free_func,
};

msg_handler_t fw_upgrade_resp_hndl = {
    .name = "fw_upgrade_resp_hndl",
    .in_check_func = fix_length_payload_check,
    .in_payload_size = sizeof(fw_upgrade_notify_resp),
    .in_msg_type = RPC_SYS_FIRMWARE_UPGRADE_RESP,
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
    rpc_client_t *cli = new_rpc_client("172.20.0.100", 9000);
    if (cli == NULL) {
        printf("new client failed\n");
        return -1;
    }
    register_msg_handler(cli, &test_hndl);
    register_msg_handler(cli, &pull_packet_hndl);
    register_msg_handler(cli, &fw_upgrade_resp_hndl);
    rpc_client_set_disconnect_cb(cli, on_disconnect);
    rpc_client_set_connect_cb(cli, on_connect);
   // rpc_client_enable_keepalive(cli);
    if (start_rpc_client(cli) < 0) {
        printf("start rpc client failed\n");
        return -1;
    }
    request_iframe_req req;
    req.sensor_id = htonl(1);

    char *filename = argv[1];
    fp = fopen(filename, "rb");
    struct stat st;
    stat(filename, &st);
    
#if 1 
    //unsigned char hash1[MD5_DIGEST_LENGTH]; // MD5散列值存储  
    unsigned char hash2[MD5_DIGEST_LENGTH]; // MD5散列值存储  
    char hex_output[MD5_DIGEST_LENGTH * 2 + 1]; // 存储十六进制字符串

    char *buf1 = malloc(st.st_size);
    fread(buf1, 1, st.st_size, fp);
    fseek(fp, 0, SEEK_SET);
    //MD5((unsigned char *)buf1, st.st_size, hash1);

    // 将散列值转换为十六进制字符串
    //bin2hex(hash1, hex_output);
    //printf("%s\n", hex_output);
    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, buf1, st.st_size);
    MD5_Final(hash2, &ctx);
    bin2hex(hash2, hex_output);
    printf("md5sum is %s\n", hex_output);
#endif
    fw_upgrade_notify notify;
    memset(&notify, 0, sizeof(notify));
    notify.request_id = htonl(123);
    strcpy(notify.fw_version, "1.0.0");
    strncpy(notify.md5_sum, hex_output, sizeof(notify.md5_su));
    file_size = st.st_size;
    printf("image size:%d\n", file_size);
    notify.fw_size = htonl(file_size);
    send_msg(cli, RPC_SYS_FIRMWARE_UPGRADE_REQ, &notify, sizeof(notify));
    while (1) {
        //send_msg(cli, RPC_SYS_TEST_REQ, &req, sizeof(req));
        sleep(5);
    }
    fclose(fp);
}

