/*
 * File: leelen_rpc.h
 * File Created: Thursday, 6th June 2024 9:52:06 am
 * Author: qiuhui (qiuhui@leelen.com)
 * -----
 * Last Modified: Thursday, 6th June 2024 9:52:26 am
 * Modified By: qiuhui (qiuhui@leelen.com>)
 * -----
 * Copyright - 2024 leelen, leelen
 */

#ifndef __LEELEN_RPC_H__
#define __LEELEN_RPC_H__

#include <stdint.h>
#include "hashmap.h"
#include "event_loop.h"
#include <mqueue.h>
#include <pthread.h>
#include <stdatomic.h>

#if defined(__cplusplus)
extern "C" {
#endif

#ifndef closesocket
#define closesocket(s)    close(s)
#endif

#define MAX_REQISTER_RPC 256
#define MAX_WORK_THREAD 16
#define DEFAULT_WORK_THREAD 1
#define DEFAULT_MAX_CONNECTIONS 1
#define MAX_MSG_BODY_SIZE 65535
#define MAX_OUTOUT_BUF 4
#define RPC_MAGIC_NUMBER 0xCAF3BA7E

/**
 * 消息头结构体定义。
 * 用于封装消息的基本信息，包括魔法数、版本号、消息来源、目标、类型、序列号和负载大小。
 * __attribute__((packed)) 确保结构体成员没有间隙，以减少内存使用和提高效率。
 */
struct msg_header_t{
    uint32_t magic_number; /**< 魔法数，用于校验消息的合法性。 */
    char version; /**< 消息版本号。 */
    uint16_t msg_source; /**< 消息来源标识。 */
    uint16_t msg_dest; /**< 消息目标标识。 */
    uint16_t msg_type; /**< 消息类型。 */
    uint16_t msg_seq; /**< 消息序列号，用于消息跟踪和重传。 */
    uint16_t payload_size; /**< 消息负载的大小。 */
}__attribute__((packed));

/**
 * 消息结构体定义。
 * 包含消息头和负载数据，负载数据的长度是可变的。
 * __attribute__((packed)) 确保结构体成员没有间隙。
 */
struct msg_t {
    struct msg_header_t header; /**< 消息头。 */
    char data[]; /**< 消息负载数据。 */
}__attribute__((packed));

/**
 * 处理结果结构体定义。
 * 用于封装处理消息后的结果，包括负载数据指针、负载大小和私有数据指针。
 */
typedef struct  {
    void *payload; /**< 负载数据指针。 */
    uint16_t payload_size; /**< 负载数据大小。 */
    void *priv_data; /**< 私有数据指针，用于处理函数内部使用。 */
} proc_result_t;

/**
 * RPC缓冲区结构体定义。
 * 用于封装RPC（远程过程调用）的请求或响应数据，包括数据指针、数据大小、偏移量和是否在使用后关闭的标志。
 */
typedef struct {
    void *data; /**< 数据指针。 */
    uint16_t data_size; /**< 数据大小。 */
    uint16_t offset; /**< 数据的偏移量。 */
    uint16_t close_after; /**< 是否在使用后关闭标志。 */
} rpc_buf_t;

/**
 * 消息处理函数类型定义。
 * 定义了处理消息的函数签名，接受上下文、负载数据和负载大小作为参数，返回处理结果。
 */
typedef proc_result_t *(*msg_proc_t)(void *ctx, void *payload, uint16_t payload_size);

/**
 * 消息释放函数类型定义。
 * 定义了释放消息负载数据的函数签名，接受数据指针作为参数。
 */
typedef void (*msg_free_func)(void *data);

/**
 * 检查入站负载函数类型定义。
 * 定义了检查入站负载数据是否合法的函数签名，接受服务标识、负载数据和负载大小作为参数，返回检查结果。
 */
typedef int (*in_payload_check)(void *svc, void *payload, uint16_t payload_size);

/* 定义RPC（Remote Procedure Call）结构体，用于封装远程过程调用的相关信息 */
typedef struct {
    /* 函数名 */
    char *name;
    
    /* 接收消息类型，用于区分不同的远程调用请求，全局唯一 */
    uint16_t in_msg_type;
    
    /* 输入负载校验函数，用于在执行业务逻辑前对传入的负载数据进行校验 */
    in_payload_check in_check_func;
    
    /* 输入负载大小，用于指定校验函数在检查负载数据时应使用的大小 */
    uint16_t in_payload_size;

    /* 回调函数，当远程调用被触发时，该函数将被调用以执行相应的业务逻辑 */
    msg_proc_t proc_func;

    /* 响应消息类型*/
    uint16_t out_msg_type;

    /* 释放函数，用于释放回调函数返回的proc_result_t结构体中的数据 */
    msg_free_func free_func;
} msg_handler_t;

/**
 * 默认的内存释放函数。
 * 
 * @param data 需要释放的内存块指针。
 */
void default_free_func(void *data);

int rpc_compare(const void *a, const void *b, void *udata);

uint64_t rpc_hash(const void *item, uint64_t seed0, uint64_t seed1);

/**
 * 固定长度负载数据检查函数。
 * 
 * @param r 类型为msg_handler_t *
 * @param payload 负载数据指针。这里未使用
 * @param payload_size 负载数据的大小。
 * @return 如果负载数据符合固定长度要求，则返回0；否则返回1。
 */
int fix_length_payload_check(void *r, void *payload, uint16_t payload_size);

/**
 * 检查消息类型是否可以注册，目前允许注册非协议层(非0x00开头)的业务消息。
 * 
 * @param msg_type 待检查的消息类型。
 * @return 如果消息类型被允许，则返回1；否则返回0。
 */
int is_allowed_msg(uint16_t msg_type);

#if defined(__cplusplus)
}
#endif  // __cplusplus

#endif //__LEELEN_RPC_H__