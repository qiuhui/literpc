/*
 * File: rpc_server.h
 * File Created: Friday, 28th June 2024 2:18:38 pm
 * Author: qiuhui (qiuhui@leelen.com)
 * -----
 * Last Modified: Friday, 28th June 2024 2:18:41 pm
 * Modified By: qiuhui (qiuhui@leelen.com>)
 * -----
 * Copyright - 2024 leelen, leelen
 */

#ifndef __RPC_SERVER_H__
#define __RPC_SERVER_H__

#include "rpc.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 定义RPC服务结构体 */
typedef struct {
    char *name; /* 服务名称 */
    uint8_t id; /* 服务ID */
    struct hashmap *hndls; /* 手柄映射表，用于存储服务的具体处理函数 */
} rpc_service;

/* 定义工作线程上下文结构体 */
typedef struct {
    int thread_idx; /* 线程索引，用于标识当前工作线程 */
    char mq_name[32]; /* 消息队列名称，用于标识工作线程的消息队列 */
    mqd_t mq; /* 消息队列描述符，用于收发消息 */
    atomic_int connections; /* 当前连接数，用于统计工作线程的连接数量 */
    pthread_mutex_t lock; /* 互斥锁，用于线程安全的操作 */
    rpc_event_loop_node *loops; /* 事件循环链表，用于管理事件循环 */
} work_thread_ctx_t;

/* 定义RPC服务器结构体 */
typedef struct {
    uint16_t port; /* 服务器监听端口 */
    struct hashmap *svcs; /* 服务映射表，用于存储注册的服务 */
    int max_connections; /* 最大连接数，用于限制服务器的连接数量 */
    atomic_int connections; /* 当前连接数，用于统计服务器的连接数量 */
    int work_threads; /* 工作线程数，用于指定服务器的工作线程数量 */
    disconnect_cb on_disconnect; /* 断开连接回调函数，用于处理连接断开事件 */
    connect_cb on_connect; /* 连接建立回调函数，用于处理连接建立事件 */
    pthread_mutex_t lock; /* 互斥锁，用于线程安全的操作 */
    int enable_keepalive;
    work_thread_ctx_t work_ctxs[MAX_WORK_THREAD]; /* 工作线程上下文数组，用于存储工作线程的上下文信息 */
} rpc_server_t;

/* 设置RPC服务器允许的最大连接数。该接口需要在rpc_server_start前调用 */
void rpc_server_set_max_connections(int max_connections);

/* 设置RPC服务器的工作线程数。该接口需要在rpc_server_start前调用 */
void rpc_server_set_work_threads(int work_threads);

/* 设置RPC客户端断开连接时的回调函。该接口需要在rpc_server_start前调用 */
void rpc_server_set_disconnect_cb(disconnect_cb cb);

/* 设置RPC客户端建连成功时的回调函数。该接口需要在rpc_server_start前调用 */
void rpc_server_set_connect_cb(connect_cb cb);

/* 注册RPC服务。该接口需要在rpc_server_start前调用 */
int register_rpc_service(rpc_service *svc);

/* 启动RPC服务器 */
int rpc_server_start(uint16_t port);

/* 向指定连接推送消息 */
int push_msg(void *ctx, uint16_t msg_type, void *payload, uint16_t payload_size);

/* 启用应用层保活 */
int rpc_server_enable_keepalive();

#ifdef __cplusplus
}
#endif // __cplusplus

#endif //__RPC_SERVER_H__