/*
 * File: event_loop.h
 * File Created: Friday, 14th June 2024 7:32:37 pm
 * Author: qiuhui (qiuhui@leelen.com)
 * -----
 * Last Modified: Friday, 14th June 2024 7:32:40 pm
 * Modified By: qiuhui (qiuhui@leelen.com>)
 * -----
 * Copyright - 2024 leelen, leelen
 */

#ifndef __EVENT_LOOP_H__
#define __EVENT_LOOP_H__

#include "fifo.h"
#include <stdint.h>
#include <stdatomic.h>


#if defined(__cplusplus)
extern "C" {
#endif

typedef enum {
    EL_NORMAL = 0,
    EL_READING_HEADER,
    EL_READING_BODY,
} event_loop_status;

typedef enum {
    RPC_CONNECTION_STATUS_CONNECTED,
    RPC_CONNECTION_STATUS_DISCONNECTED,
    RPC_CONNECTION_STATUS_ERROR,
} rpc_connection_status;

typedef void (*disconnect_cb)(const void *ctx);
typedef void (*connect_cb)(const void *ctx);

/* 定义RPC事件循环结构体 */
typedef struct rpc_event_loop {
    /* 套接字文件描述符，用于网络通信 */
    int sock_fd;
    /* 对端IP地址，用于标识连接的对端 */
    char peer_ip[32];
    /* 对端端口号，用于标识连接的对端 */
    uint16_t peer_port;
    /* 接收的请求头缓冲区，用于存储接收到的请求头数据 */
    char *in_header;
    /* 已接收的请求头长度，用于记录已接收到的请求头数据的长度 */
    uint16_t recvd_in_header;
    /* 事件循环状态，用于表示当前事件循环的状态 */
    event_loop_status status;
    /* 已接收的消息类型，用于标识接收到的消息的类型 */
    uint16_t recvd_msg_type;
    /* 已接收的消息序列号，用于标识接收到的消息的序列号 */
    uint16_t recvd_msg_seq;
    /* 接收的消息体缓冲区，用于存储接收到的消息体数据 */
    char *in_body;
    /* 已接收的消息体长度，用于记录已接收到的消息体数据的长度 */
    uint16_t recvd_in_body;
    /* 消息体的预期大小，用于表示期望接收的消息体的大小 */
    uint16_t in_body_size;
    /* 连接状态，用于表示当前连接的状态 */
    rpc_connection_status conn_status;
    /* 是否关闭连接的标志，用于表示是否应该关闭当前连接 */
    uint16_t close_conn;
    /* 消息序列号，用于为发送的消息分配序列号 */
    atomic_ushort seq;
    /* 发送消息的缓冲区，用于存储待发送的消息 */
    fifo *out_msg_buf;
    /* 接收缓冲区，用于存储接收的数据 */
    char *recv_buf;
    /* 消息头的格式定义，用于表示消息头的结构 */
    const void *msg_header;
    /* 断开连接时的回调函数，用于在断开连接时执行特定的操作 */
    disconnect_cb on_disconnect;
    /* 连接建立时的回调函数，用于在连接建立时执行特定的操作 */
    connect_cb on_connect;
    /* 最后一次收到心跳包时间 */
    atomic_ullong recv_heartbeat_time;
    /* 最后一次发送心跳包时间 */
    uint64_t send_heartbeat_time;
    /* 下一个事件循环，用于构建事件循环链表 */
    struct rpc_event_loop *next;
} rpc_event_loop;


typedef struct rpc_event_loop_node {
    rpc_event_loop *data;
    struct rpc_event_loop_node *next;
}rpc_event_loop_node;


rpc_event_loop_node *create_rpc_event_loop(rpc_event_loop *loop);

void insert_rpc_event_loop(rpc_event_loop_node **head, rpc_event_loop *loop);

void delete_rpc_event_loop(rpc_event_loop_node **head, rpc_event_loop *loop);

#if defined(__cplusplus)
}
#endif  // __cplusplus

#endif
