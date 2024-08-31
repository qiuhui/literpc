/*
 * File: rpc_client.h
 * File Created: Friday, 28th June 2024 2:15:30 pm
 * Author: qiuhui (qiuhui@leelen.com)
 * -----
 * Last Modified: Friday, 28th June 2024 2:15:33 pm
 * Modified By: qiuhui (qiuhui@leelen.com>)
 * -----
 * Copyright - 2024 leelen, leelen
 */
#ifndef __RPC_CLIENT_H__
#define __RPC_CLIENT_H__

#include <pthread.h>
#include "rpc.h"

#ifdef __cplusplus
extern "C" {
#endif

/* RPC客户端结构体 */
typedef struct {
    char server_addr[32]; /* 服务器地址 */
    uint16_t server_port; /* 服务器端口 */
    rpc_event_loop *lp;   /* 事件循环句柄 */
    int enable_keepalive;
    pthread_mutex_t lock;
    atomic_int status;
    struct hashmap *hndls; /* 消息处理函数映射表 */
    pthread_t tid;
} rpc_client_t;

/**
 * 创建一个新的RPC客户端实例
 * @param ip 服务器的IP地址
 * @param port 服务器的端口号
 * @return 新创建的RPC客户端实例的指针
 */
rpc_client_t *new_rpc_client(char *ip, uint16_t port);


/**
 * 
 * 注册消息处理函数。在new_rpc_client之后，connect_server之前调用该接口注册handler
 * @param client RPC客户端实例指针
 * @param r 消息处理函数指针
 * @return 注册结果，0表示成功，非0表示失败
 */
int register_msg_handler(rpc_client_t *client, msg_handler_t *r);

/**
 * 设置连接断开回调函数
 * @param c RPC客户端实例指针
 * @param cb 连接断开时调用的回调函数指针
 */
void rpc_client_set_disconnect_cb(rpc_client_t *c, disconnect_cb cb);

/**
 * 设置连接成功回调函数
 * @param c RPC客户端实例指针
 * @param cb 连接成功时调用的回调函数指针
 */
void rpc_client_set_connect_cb(rpc_client_t *c, connect_cb cb);

int rpc_client_enable_keepalive(rpc_client_t *c);

/**
 * 启动RPC客户端
 * @param c RPC客户端实例指针
 * @return 启动结果，0表示成功，非0表示失败
 */
int start_rpc_client(rpc_client_t *c);

/**
 * 发送消息
 * @param c RPC客户端实例指针
 * @param msg_type 消息类型
 * @param payload 消息载荷指针
 * @param payload_size 消息载荷大小
 * @return 发送结果，0表示成功，非0表示失败
 */
int send_msg(const rpc_client_t *c, uint16_t msg_type, void *payload, uint16_t payload_size);

int stop_rpc_client(rpc_client_t *c);


#ifdef __cplusplus
}
#endif // __cplusplus

#endif //__RPC_CLIENT_H__
