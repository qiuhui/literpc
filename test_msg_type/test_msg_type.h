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

#ifndef TEST_MSG_H
#define TEST_MSG_H

#if defined(__cplusplus)
extern "C" {
#endif  // __cplusplus


typedef enum {
    RPC_SYS_TEST_REQ = 0x0100,
    RPC_SYS_TEST_RESP = 0x0101,
} test_rpc_msg_e;

#if defined(__cplusplus)
}
#endif  // __cplusplus

#endif //TEST_MSG_H



