/*
 * File: leelen_rpc.c
 * File Created: Thursday, 6th June 2024 10:20:42 am
 * Author: qiuhui (qiuhui@leelen.com)
 * -----
 * Last Modified: Thursday, 6th June 2024 10:20:44 am
 * Modified By: qiuhui (qiuhui@leelen.com>)
 * -----
 * Copyright - 2024 leelen, leelen
 */

#include <mqueue.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <assert.h>
#include <sys/time.h>
#include "rpc_server.h"
#include "hashmap.h"
#include "fifo.h"
#include "internal_msg_type.h"
#include "util.h"

#define RECV_BUF_SIZE 1024
#define HEARTBEAT_INTERVAL 1000
#define HEARTBEAT_TIMEOUT 3000

typedef struct {
    int sock_fd;
    char peer_ip[32];
    uint16_t peer_port;
} newconn_notify_t;

static uint64_t seed0 = 0x1234567887654321;
static uint64_t seed1 = 0x8765432112345678;
static char serv_version = 1;
static rpc_server_t rpc_server = {
    .max_connections = DEFAULT_MAX_CONNECTIONS,
    .work_threads = DEFAULT_WORK_THREAD,
    .port = 9000,
};

static const char *RPC_SERVER_TAG = "rpc_server";
static int service_compare(const void *a, const void *b, void *udata) {
    const rpc_service *sa = a;
    const rpc_service *sb = b;
    return sa->id != sb->id;
}

static uint64_t service_hash(const void *item, uint64_t seed0, uint64_t seed1) {
    const rpc_service *s = item;
    char key[32] = {0};

    snprintf(key, sizeof(key), "%d", s->id);
    return hashmap_sip(key, strlen(key), seed0, seed1);
}

static msg_handler_t *search_rpc(uint16_t msg_type) {
    uint8_t svc_id = (uint8_t)(msg_type >> 8);
    const rpc_service *svc = (const rpc_service *)hashmap_get(rpc_server.svcs, &(rpc_service){.id = svc_id});
    if (svc == NULL) {
        return NULL;
    }
    return (msg_handler_t *)hashmap_get(svc->hndls, &(msg_handler_t){.in_msg_type = msg_type});
}

static proc_result_t *errhndl(void *ctx, void *payload, uint16_t payload_size)
{
    rpc_event_loop *loop = (rpc_event_loop *)ctx;
    printf("receive err msg 0x%04x\n", loop->recvd_msg_type);
    return NULL;
}

static proc_result_t *heartbeat_req_hndl(void *ctx, void *payload, uint16_t payload_size)
{
    proc_result_t *output = malloc(sizeof(proc_result_t));
    output->priv_data = NULL;
    output->payload = NULL;
    output->payload_size = 0;
    
    return output;
}

static proc_result_t *heartbeat_resp_hndl(void *ctx, void *payload, uint16_t payload_size)
{
    rpc_event_loop *loop = (rpc_event_loop *)ctx;
    atomic_store(&loop->recv_heartbeat_time, get_time_ms());
    
    return NULL;
}

static msg_handler_t heartbeat_hndls[] = {
    { 
        .name = "RPC_SYS_HEARTBEAT_REQ",
        .in_msg_type = RPC_SYS_HEARTBEAT_REQ, 
        .in_payload_size = 0, 
        .in_check_func = NULL, 
        .proc_func = heartbeat_req_hndl,
        .out_msg_type = RPC_SYS_HEARTBEAT_RESP,
        .free_func = default_free_func,
    },
    { 
        .name = "RPC_SYS_HEARTBEAT_RESP",
        .in_msg_type = RPC_SYS_HEARTBEAT_RESP,
        .in_payload_size = 0, 
        .in_check_func = NULL, 
        .proc_func = heartbeat_resp_hndl,
        .free_func = NULL,
    },
};

static msg_handler_t err_hndls[] = {
    {
        .name = "RPC_SYS_ERR_MAGIC_NUMBER",
        .in_msg_type = RPC_SYS_ERR_MAGIC_NUMBER, 
        .in_payload_size = 0, 
        .in_check_func = NULL, 
        .proc_func = errhndl,
        .free_func = NULL,
    },
    { 
        .name = "RPC_SYS_ERR_UNKNOWN_MSG",
        .in_msg_type = RPC_SYS_ERR_UNKNOWN_MSG, 
        .in_payload_size = 0, 
        .in_check_func = NULL, 
        .proc_func = errhndl,
        .free_func = NULL,
    },
    { 
        .name = "RPC_SYS_ERR_VERSION",
        .in_msg_type = RPC_SYS_ERR_VERSION, 
        .in_payload_size = 0, 
        .in_check_func = NULL, 
        .proc_func = errhndl,
        .free_func = NULL,
    },
    { 
        .name = "RPC_SYS_ERR_INTERNAL",
        .in_msg_type = RPC_SYS_ERR_INTERNAL, 
        .in_payload_size = 0, 
        .in_check_func = NULL, 
        .proc_func = errhndl,
        .free_func = NULL,   
    },
    { 
        .name = "RPC_SYS_ERR_PAYLOAD_CHECK",
        .in_msg_type = RPC_SYS_ERR_PAYLOAD_CHECK, 
        .in_payload_size = 0, 
        .in_check_func = NULL, 
        .proc_func = errhndl,
        .free_func = NULL,
    },
    { 
        .name = "RPC_SYS_ERR_UNKNOWN",
        .in_msg_type = RPC_SYS_ERR_UNKNOWN, 
        .in_payload_size = 0, 
        .in_check_func = NULL, 
        .proc_func = errhndl,
        .free_func = NULL,
    },
};

int register_rpc_service(rpc_service *svc)
{
    if (rpc_server.svcs == NULL) {
        rpc_server.svcs = hashmap_new(sizeof(rpc_service), 0, seed0, seed1, 
                                     service_hash, service_compare, NULL, NULL);
    }
    
    assert(svc->id > 0x00 && hashmap_get(rpc_server.svcs, &(rpc_service){.id = svc->id}) == NULL);

    hashmap_set(rpc_server.svcs, (const void *)svc);

    return 0;
}

static void do_send(rpc_event_loop *loop)
{
    while (1) {
        if (fifo_empty(loop->out_msg_buf)) {
            break;
        }
        rpc_buf_t *msg = (rpc_buf_t *)fifo_pop(loop->out_msg_buf);
        while (1) {
            int ret = send(loop->sock_fd, (char *)msg->data + msg->offset, msg->data_size - msg->offset, MSG_NOSIGNAL);
            if (ret == 0) {
                loop->conn_status = RPC_CONNECTION_STATUS_DISCONNECTED;
                break;
            }
            if (ret < 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                    loop->close_conn = 1;
                    break;
                }
                continue;
            }

            msg->offset += ret;
            if (msg->offset == msg->data_size) {
                break;
            }
        }

        int close = msg->close_after;
        free(msg->data);
        free(msg);

        if (close || loop->close_conn || loop->conn_status == RPC_CONNECTION_STATUS_DISCONNECTED) {
            loop->conn_status = RPC_CONNECTION_STATUS_DISCONNECTED;
            printf("[%s] need close, stop sending data\n", RPC_SERVER_TAG);
            break;
        }
    }
}

static void send_msg_now(rpc_event_loop *loop, uint16_t msg_type, void *payload, uint16_t payload_size) 
{
    int msg_size = sizeof(struct msg_t) + payload_size;
    struct msg_t *msg = malloc(msg_size);
    msg->header.magic_number = htonl(RPC_MAGIC_NUMBER);
    msg->header.version = serv_version;
    msg->header.msg_source = 0;
    msg->header.msg_dest = 0;
    msg->header.msg_type = htons(msg_type);
    msg->header.payload_size = htons(payload_size);
    msg->header.msg_seq = htons(atomic_fetch_add(&loop->seq, 1));
    if (payload_size > 0 && payload != NULL) {
        memcpy(msg->data, payload, payload_size);
    }
    
    int sent = 0;
    while (sent < msg_size) {
        int ret = send(loop->sock_fd, (char *)msg + sent, msg_size - sent, MSG_NOSIGNAL);
        if (ret == 0) {
            loop->conn_status = RPC_CONNECTION_STATUS_DISCONNECTED;
            return;
        }
        if (ret < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK  && errno != EINTR) {
                loop->close_conn = 1;
                break;
            }
            continue;
        }
        sent += ret;
    }
    free(msg);
}

static int is_loop_exist(rpc_event_loop *loop)
{
    int i;

    int exist = 0;

    for (i = 0; i < rpc_server.work_threads; i++) {
        pthread_mutex_lock(&rpc_server.work_ctxs[i].lock);
        rpc_event_loop_node *p = rpc_server.work_ctxs[i].loops;
        while (p != NULL) {
            if (p->data == loop) {
                exist = 1;
                break;
            }
        }
        pthread_mutex_unlock(&rpc_server.work_ctxs[i].lock);
        if (exist) {
            break;
        }
    }

    return exist;
}

static int __push_msg(rpc_event_loop *loop, uint16_t msg_type, void *payload, uint16_t payload_size) 
{
    rpc_buf_t *buf = malloc(sizeof(rpc_buf_t));

    int msg_size = sizeof(struct msg_t) + payload_size;
    struct msg_t *msg = malloc(msg_size);
    msg->header.magic_number = htonl(RPC_MAGIC_NUMBER);
    msg->header.version = serv_version;
    msg->header.msg_source = 0;
    msg->header.msg_dest = 0;
    msg->header.msg_type = htons(msg_type);
    msg->header.payload_size = htons(payload_size);
    if (payload_size > 0 && payload != NULL) {
        memcpy(msg->data, payload, payload_size);
    }
    msg->header.msg_seq = htons(atomic_fetch_add(&loop->seq, 1));
  
    buf->data = (void *)msg;
    buf->data_size = msg_size;
    buf->close_after = 0;
    buf->offset = 0;

    fifo_push(loop->out_msg_buf, (void *)buf);
    return 0;
}

int push_msg(void *ctx, uint16_t msg_type, void *payload, uint16_t payload_size) 
{
    if (ctx == NULL) {
        return -1;
    }
    rpc_event_loop *loop = (rpc_event_loop *)ctx;
    if (!is_loop_exist(loop)) {
        return -2;
    }
    return __push_msg(loop, msg_type, payload, payload_size);
}

static void send_err_msg(rpc_event_loop *loop, rpc_sys_msg_e err_msg_type, uint16_t is_fatal_err)
{
    send_msg_now(loop, err_msg_type, NULL, 0);
    loop->close_conn = is_fatal_err;
}

static int check_header(rpc_event_loop *loop, struct msg_header_t *header)
{
    uint32_t magic_number = ntohl(header->magic_number);

    if (magic_number != RPC_MAGIC_NUMBER) {
        printf("[%s] magic_number not match\n", RPC_SERVER_TAG);
        send_err_msg(loop, RPC_SYS_ERR_MAGIC_NUMBER, 1);
        return -1;
    }

    char version = header->version;
    if (version != serv_version) {
        printf("[%s] version not match, server_version:%d, msg_version: %d\n", RPC_SERVER_TAG, serv_version, version);
        send_err_msg(loop, RPC_SYS_ERR_VERSION, 1);
        return -1;
    }

    uint16_t msg_type = ntohs(header->msg_type);
    if (msg_type == 0) {
        printf("[%s] message type can not be 0\n", RPC_SERVER_TAG);
        send_err_msg(loop, RPC_SYS_ERR_UNKNOWN_MSG, 0);
        return -1;
    }

    return 0;
}

static void do_process(rpc_event_loop *loop)
{
    proc_result_t *out = NULL;

    const msg_handler_t *r = search_rpc(loop->recvd_msg_type);
    if (r == NULL) {
        printf("[%s] unknown message type 0x%04x\n", RPC_SERVER_TAG, loop->recvd_msg_type);
        send_err_msg(loop, RPC_SYS_ERR_UNKNOWN_MSG, 0);
        goto reset_ev;
    }

    if (r->in_check_func && r->in_check_func((void *)r, loop->in_body, loop->in_body_size)) {
        printf("[%s] payload check failed. msg_seq: %d, payload_size:%d \n", RPC_SERVER_TAG, loop->recvd_msg_seq, loop->in_body_size);
        send_err_msg(loop, RPC_SYS_ERR_PAYLOAD_CHECK, 0);
        goto reset_ev;
    }
    out = r->proc_func(loop, loop->in_body, loop->in_body_size);
    if (out != NULL) {
        send_msg_now(loop, r->out_msg_type, out->payload, out->payload_size);
    }
reset_ev:
    if (out && r->free_func) {
        r->free_func(out);
    }
    loop->in_body_size = 0;
    loop->recvd_in_body = 0;
    loop->status = EL_NORMAL;
    loop->recvd_msg_type = 0;
    loop->recvd_msg_seq = 0;
    loop->recvd_in_header = 0;
    loop->msg_header = NULL;
}

static void do_recv(rpc_event_loop *loop)
{
    int header_len = sizeof(struct msg_header_t);
    char *buf = loop->recv_buf;

    int recvd = recv(loop->sock_fd, buf, RECV_BUF_SIZE, 0);
    if (recvd == 0) {
        loop->conn_status = RPC_CONNECTION_STATUS_DISCONNECTED;
        return;
    }
    if (recvd < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK  && errno != EINTR) {
            // 其他错误
            send_err_msg(loop, RPC_SYS_ERR_UNKNOWN, 1);
        }
        return;
    }
    
    int left = recvd;

    while (left > 0) {
        if (loop->status == EL_NORMAL) {
            if (left >= header_len) {
                struct msg_header_t *h = (struct msg_header_t *)(buf + recvd - left);
                if (check_header(loop, h) != 0) {
                    printf("[%s] check header failed\n", RPC_SERVER_TAG);
                    break;
                }
                left -= header_len;
                loop->recvd_msg_type = ntohs(h->msg_type);
                loop->recvd_msg_seq = ntohs(h->msg_seq);
                loop->in_body_size = ntohs(h->payload_size);
                loop->msg_header = (void *)h;
                if (loop->in_body_size == 0) {
                    do_process(loop);
                } else {
                    loop->status = EL_READING_BODY;
                }
                continue;
            } else {
                loop->status = EL_READING_HEADER;
                continue;
            }
        }

        if (loop->status == EL_READING_HEADER) {
            int wait_header = header_len - loop->recvd_in_header;
            if (left < wait_header) {
                memcpy(loop->in_header + loop->recvd_in_header, buf + recvd - left, left);
                loop->recvd_in_header += left;
                break;
            }
            memcpy(loop->in_header + loop->recvd_in_header, buf + recvd - left, wait_header);
            left -= wait_header;
            loop->recvd_in_header = 0;
            struct msg_header_t *h = (struct msg_header_t *)loop->in_header;
            if (check_header(loop, h) != 0) {
                break;
            }
            loop->in_body_size = ntohs(h->payload_size);
            loop->recvd_msg_type = ntohs(h->msg_type);
            loop->recvd_msg_seq = ntohs(h->msg_seq);
            loop->msg_header = (void *)h;
            if (loop->in_body_size == 0) {
                do_process(loop);
            } else {
                loop->status = EL_READING_BODY;
            }
            continue;
        }

        if (loop->status == EL_READING_BODY) {
            int wait_body = loop->in_body_size - loop->recvd_in_body;
            if (left < wait_body) {
                memcpy(loop->in_body + loop->recvd_in_body, buf + recvd - left, left);
                loop->recvd_in_body += left;
                break;
            }

            if (wait_body > 0) {
                memcpy(loop->in_body + loop->recvd_in_body, buf + recvd - left, wait_body);
            }
            do_process(loop);
            left -= wait_body;
            continue;
        }
    }
}

static void *_rpc_work_handler(void *arg)
{
    fd_set rfds, wfds;
    work_thread_ctx_t *ctx = (work_thread_ctx_t *)arg;

    while (1) {
        int i;

        /* 先检查有没有新连接，如果有新连接，就加入event列表。
           当前alios的mqueue未实现getattr接口，无法知道当前队列有多少消息，
           只能先通过循环调用receive来尽可能多获取消息
        */
        for (i = 0; i < 3; i++) {
            newconn_notify_t notify;
            ssize_t msg_size = mq_timedreceive(ctx->mq, (char *)&notify, sizeof(notify), NULL, NULL);
            if (msg_size < 0) {
                continue;
            }
            printf("[%s] new connection received from %s:%d, socket %d\n", RPC_SERVER_TAG, notify.peer_ip, notify.peer_port, notify.sock_fd);
            rpc_event_loop *lp = (rpc_event_loop *)malloc(sizeof(rpc_event_loop));
            memset(lp, 0, sizeof(rpc_event_loop));
            lp->sock_fd = notify.sock_fd;
            strcpy(lp->peer_ip, notify.peer_ip);
            lp->peer_port = notify.peer_port;
            lp->in_header = (char *)malloc(sizeof(struct msg_header_t));
            lp->in_body = (char *)malloc(MAX_MSG_BODY_SIZE);
            lp->recv_buf = (char *)malloc(RECV_BUF_SIZE);
            lp->out_msg_buf = malloc(sizeof(fifo));
            if (rpc_server.on_disconnect) {
                lp->on_disconnect = rpc_server.on_disconnect;
            }
            if (rpc_server.on_connect) {
                lp->on_connect = rpc_server.on_connect;
            }
            fifo_init(lp->out_msg_buf, free);
            if (rpc_server.enable_keepalive) {
                lp->recv_heartbeat_time = ATOMIC_VAR_INIT(0);
                lp->send_heartbeat_time = get_time_ms();
                atomic_store(&lp->recv_heartbeat_time, lp->send_heartbeat_time);
            }
            
            pthread_mutex_lock(&ctx->lock);
            if (ctx->loops == NULL) {
                ctx->loops = create_rpc_event_loop(lp);
            } else {
                insert_rpc_event_loop(&ctx->loops, lp);
            }
            pthread_mutex_unlock(&ctx->lock);

            if (lp->on_connect) {
                lp->on_connect(lp);
            }
        }

        if (ctx->loops == NULL) {
            usleep(100000);
            continue;
        }
        
        rpc_event_loop_node *lpn = ctx->loops;

        while (lpn != NULL) {
            rpc_event_loop_node *next = lpn->next;

            int64_t time_ms = get_time_ms();

            if (rpc_server.enable_keepalive) {
                if (time_ms > lpn->data->send_heartbeat_time + HEARTBEAT_INTERVAL) {
                    __push_msg(lpn->data, RPC_SYS_HEARTBEAT_REQ, NULL, 0);
                    lpn->data->send_heartbeat_time = time_ms;
                }

                if (time_ms > atomic_load(&lpn->data->recv_heartbeat_time) + HEARTBEAT_TIMEOUT) {
                    printf("[%s] heartbeat timeout\n", RPC_SERVER_TAG);
                    lpn->data->close_conn = 1;
                    goto check_status;
                }
            }
            
            int need_send = !fifo_empty(lpn->data->out_msg_buf);
            FD_ZERO(&wfds);
            FD_ZERO(&rfds);
            
            FD_SET(lpn->data->sock_fd, &rfds);
            if (need_send) {
                FD_SET(lpn->data->sock_fd, &wfds);
            }

            struct timeval tv = {.tv_sec = 0, .tv_usec = 10000};
            int retval;
            if (need_send) {
                retval = select(lpn->data->sock_fd + 1, &rfds, &wfds, NULL, &tv);
            } else {
                retval = select(lpn->data->sock_fd + 1, &rfds, NULL, NULL, &tv);
            }

            if (retval < 0) {
                printf("[%s] select failed\n", RPC_SERVER_TAG);
                goto next_node;
            }

            if (retval == 0){
                goto next_node;
            }

            if (FD_ISSET(lpn->data->sock_fd, &rfds)) {
                do_recv(lpn->data);
            }

            if (need_send && FD_ISSET(lpn->data->sock_fd, &wfds)) {
                do_send(lpn->data);
            }

            check_status:
            if (lpn->data->conn_status == RPC_CONNECTION_STATUS_DISCONNECTED || lpn->data->close_conn) {
                printf("[%s] close connection from %s:%d, socket %d\n", RPC_SERVER_TAG, lpn->data->peer_ip, lpn->data->peer_port, lpn->data->sock_fd);
                rpc_event_loop *loop = lpn->data;
                if (loop->on_disconnect) {
                    loop->on_disconnect(loop);
                }
                pthread_mutex_lock(&ctx->lock);
                delete_rpc_event_loop(&ctx->loops, lpn->data);
                pthread_mutex_unlock(&ctx->lock);
                closesocket(loop->sock_fd);
                free(loop->in_header);
                free(loop->in_body);
                free(loop->recv_buf);
                fifo_destroy(loop->out_msg_buf);
                free(loop->out_msg_buf);
                free(loop);
                atomic_fetch_sub(&rpc_server.connections, 1);
                atomic_fetch_sub(&ctx->connections, 1);
                printf("[%s] current connections %d\n", RPC_SERVER_TAG, atomic_load(&rpc_server.connections));
            }

            next_node:
            lpn = next;
        }
    }

    return NULL;
}

static rpc_service protocol_svc = {
    .name = "protocol_service", 
    .id = 0x00, 
};

int rpc_server_init()
{
    if (rpc_server.svcs == NULL) {
        rpc_server.svcs = hashmap_new(sizeof(rpc_service), 0, seed0, seed1, 
                                     service_hash, service_compare, NULL, NULL);
    } else {
        int cnt = hashmap_count(rpc_server.svcs);
        if (cnt == 0) {
            printf("[%s] no handler!!!\n", RPC_SERVER_TAG);
        } else {
            printf("[%s] %d service registered", RPC_SERVER_TAG, cnt);
            size_t iter = 0;
            void *item;
            while (hashmap_iter(rpc_server.svcs, &iter, &item)) {
                const rpc_service *svc = (const rpc_service *)item;
                printf("[%s] service %s registered, %d handlers below ===\n", RPC_SERVER_TAG, svc->name, (int)hashmap_count(svc->hndls));
                size_t hiter = 0;
                void *hitem;
                while (hashmap_iter(svc->hndls, &hiter, &hitem)) {
                    const msg_handler_t *hndl = (const msg_handler_t *)hitem;
                    printf("[%s] %s | %s\n", RPC_SERVER_TAG, svc->name, hndl->name);
                }
            }
        }
    }

    if (protocol_svc.hndls == NULL) {
        protocol_svc.hndls = hashmap_new(sizeof(msg_handler_t), 0, 0, 0, rpc_hash, rpc_compare, NULL, NULL);
    }

    int i;
    for (i = 0; i < sizeof(err_hndls) / sizeof(err_hndls[0]); i++) {
        hashmap_set(protocol_svc.hndls, &err_hndls[i]);
    }
    
    hashmap_set(rpc_server.svcs, (void *)&protocol_svc);

    if (rpc_server.work_threads <= 0) {
        rpc_server.work_threads = DEFAULT_WORK_THREAD;
    } else if (rpc_server.work_threads > MAX_WORK_THREAD) {
        rpc_server.work_threads = MAX_WORK_THREAD;
    }

    rpc_server.connections =  ATOMIC_VAR_INIT(0);
    
    for (i = 0; i < rpc_server.work_threads; i++) {
        char mq_name[32] = {0};
        snprintf(mq_name, sizeof(mq_name), "/rpc_work_mq_%d", i);
        struct mq_attr attr = {.mq_maxmsg = 10, .mq_msgsize = sizeof(newconn_notify_t)};
        int mqfd = mq_open(mq_name, O_RDWR | O_CREAT | O_NONBLOCK, 0644, &attr);
        if (mqfd < 0) {
            printf("[%s] mq_open failed: %d\n", RPC_SERVER_TAG, mqfd);
            return -1;
        }
        rpc_server.work_ctxs[i].mq = mqfd;
        rpc_server.work_ctxs[i].connections = ATOMIC_VAR_INIT(0);
        rpc_server.work_ctxs[i].thread_idx = i;
        rpc_server.work_ctxs[i].loops = NULL;
        pthread_mutex_init(&rpc_server.work_ctxs[i].lock, NULL);

        pthread_t pthreadId;
	    pthread_create(&pthreadId, NULL, _rpc_work_handler, &rpc_server.work_ctxs[i]);
        char work_thread_name[32] = {0};
        snprintf(work_thread_name, sizeof(work_thread_name), "rpc_work_%d", i);
        pthread_setname_np(pthreadId, work_thread_name);
    }

    return 0;
}

void rpc_server_set_max_connections(int max_connections)
{
    rpc_server.max_connections = max_connections;
}

void rpc_server_set_work_threads(int work_threads)
{
    rpc_server.work_threads = work_threads;
}

void rpc_server_set_disconnect_cb(disconnect_cb cb)
{
    rpc_server.on_disconnect = cb;
}

int rpc_server_enable_keepalive()
{
    rpc_server.enable_keepalive = 1;

    if (protocol_svc.hndls == NULL) {
        protocol_svc.hndls = hashmap_new(sizeof(msg_handler_t), 0, 0, 0, rpc_hash, rpc_compare, NULL, NULL);
    }

    int i;
    for (i = 0; i < sizeof(heartbeat_hndls) / sizeof(heartbeat_hndls[0]); i++) {
        hashmap_set(protocol_svc.hndls, &heartbeat_hndls[i]);
    }

    return 0;
}
void rpc_server_set_connect_cb(connect_cb cb)
{
    rpc_server.on_connect = cb;
}

static int select_work_thread()
{
    int i;
    int min_connection = 0;
    int select_work = 0;

    for (i = 0; i < rpc_server.work_threads; i++) {
        int work_conn = atomic_load(&rpc_server.work_ctxs[i].connections);
	    if (work_conn <= min_connection) {
	        min_connection = work_conn;
            select_work = i;
	    }
    }

   return select_work;
}

static void *rpc_main(void *arg)
{
    int listen_fd;
    struct sockaddr_in client_address;
    int opt = 1;
    int addrlen = sizeof(client_address);

    if (rpc_server_init() < 0) {
        return NULL;
    }

    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd == 0)
    {
        printf("[%s] socket error\n", RPC_SERVER_TAG);
        return NULL;
    }
    int enable = 1;
    if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0) {
        printf("[%s] error enabling SO_REUSEADDR (%d)\n", RPC_SERVER_TAG, errno);
    }
    
    struct sockaddr_in s_addr;
    memset(&s_addr, 0, sizeof(s_addr));
    s_addr.sin_family = AF_INET;
    s_addr.sin_port = htons(rpc_server.port);
    s_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(listen_fd, (struct sockaddr *)&s_addr, sizeof(struct sockaddr_in)) < 0)
    {
        printf("[%s] Failed to bind port %d.\n", RPC_SERVER_TAG, rpc_server.port);
        return NULL;
    }

    if (listen(listen_fd, 5) < 0) {
        printf("[%s] Failed to listen.\n", RPC_SERVER_TAG);
        return NULL;
    }
    
    while (true) {
        int new_socket;

        if ((new_socket = accept(listen_fd, (struct sockaddr *)&client_address, (socklen_t*)&addrlen)) < 0) {
            printf("[%s] accept failed.\n", RPC_SERVER_TAG);
            break;
        }

        if (atomic_load(&rpc_server.connections) >= rpc_server.max_connections) {
            closesocket(new_socket);
            printf("[%s] too many connections\n",RPC_SERVER_TAG);
            continue;
        }

        printf("[%s] accept new socket %d\n", RPC_SERVER_TAG, new_socket);

        setsockopt(new_socket, SOL_SOCKET, SO_REUSEADDR | SO_KEEPALIVE, &opt, sizeof(opt));
        int flags;
        flags = fcntl(new_socket, F_GETFL, 0);
        if (flags >= 0) {
            flags |= O_NONBLOCK;
            fcntl(new_socket, F_SETFL, flags);
        }
        
        int work_idx = select_work_thread();
        newconn_notify_t notify;
        notify.sock_fd = new_socket;
        inet_ntop(AF_INET, &client_address.sin_addr, notify.peer_ip, INET_ADDRSTRLEN);
        notify.peer_port = ntohs(client_address.sin_port);
        printf("[%s] send socket %d to thread %d\n", RPC_SERVER_TAG, new_socket, work_idx);
        mq_send(rpc_server.work_ctxs[work_idx].mq, (char *)&notify, sizeof(notify), 0);
        atomic_fetch_add(&rpc_server.work_ctxs[work_idx].connections, 1);
        atomic_fetch_add(&rpc_server.connections, 1);
    }
 
    // 关闭监听socket
    closesocket(listen_fd);
    return NULL;
}

int rpc_server_start(uint16_t port)
{
    pthread_t pthreadId;

    rpc_server.port = port;
	pthread_create(&pthreadId, NULL, rpc_main, NULL);
    char threadname[32] = {0};
    snprintf(threadname, sizeof(threadname), "rpc_server_main");
	pthread_setname_np(pthreadId, threadname);
    return 0;
}