/*
 * File: msg.h
 * File Created: Tuesday, 18th June 2024 10:09:35 am
 * Author: qiuhui (qiuhui@leelen.com)
 * -----
 * Last Modified: Tuesday, 18th June 2024 10:09:38 am
 * Modified By: qiuhui (qiuhui@leelen.com>)
 * -----
 * Copyright - 2024 leelen, leelen
 */

#ifndef MSG_H
#define MSG_H

#if defined(__cplusplus)
extern "C" {
#endif  // __cplusplus


typedef enum {
    /* 协议层消息码 */
    RPC_SYS_ERR_MAGIC_NUMBER = 0x0001,
    RPC_SYS_ERR_UNKNOWN_MSG = 0x0002,
    RPC_SYS_ERR_VERSION = 0x0003,
    RPC_SYS_ERR_INTERNAL = 0x0004,
    RPC_SYS_ERR_PAYLOAD_CHECK = 0x0005,

    RPC_SYS_HEARTBEAT_REQ = 0x0010,
    RPC_SYS_HEARTBEAT_RESP = 0x0011,

    RPC_SYS_ERR_UNKNOWN_SERVICE = 0x00fe,
    RPC_SYS_ERR_UNKNOWN = 0x00ff,
} rpc_sys_msg_e;

#if defined(__cplusplus)
}
#endif  // __cplusplus

#endif



