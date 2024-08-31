/*
 * File: rpc_common.c
 * File Created: Monday, 24th June 2024 11:44:44 am
 * Author: qiuhui (qiuhui@leelen.com)
 * -----
 * Last Modified: Monday, 24th June 2024 11:44:47 am
 * Modified By: qiuhui (qiuhui@leelen.com>)
 * -----
 * Copyright - 2024 leelen, leelen
 */

#include <string.h>
#include <stdlib.h>
#include "rpc.h"

int rpc_compare(const void *a, const void *b, void *udata) {
    const msg_handler_t *ra = a;
    const msg_handler_t *rb = b;
    return ra->in_msg_type != rb->in_msg_type;
}

uint64_t rpc_hash(const void *item, uint64_t seed0, uint64_t seed1) {
    const msg_handler_t *r = item;
    char key[32] = {0};

    snprintf(key, sizeof(key), "%d", r->in_msg_type);
    return hashmap_sip(key, strlen(key), seed0, seed1);
}

int fix_length_payload_check(void *r, void *payload, uint16_t payload_size)
{
    return ((msg_handler_t *)r)->in_payload_size != payload_size;
}

void default_free_func(void *data)
{
    proc_result_t *out = (proc_result_t *)data;
    if (out->payload) {
        free(out->payload);
    }
    if (out->priv_data) {
        free(out->priv_data);
    }

    free(out);
}

int is_allowed_msg(uint16_t msg_type)
{
    return msg_type >> 8;
}