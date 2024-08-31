/*
 * File: rpc_client.c
 * File Created: Monday, 17th June 2024 8:05:58 pm
 * Author: qiuhui (qiuhui@leelen.com)
 * -----
 * Last Modified: Monday, 17th June 2024 8:06:03 pm
 * Modified By: qiuhui (qiuhui@leelen.com>)
 * -----
 * Copyright - 2024 leelen, leelen
 */


#include "rpc_client.h"
#include <sys/socket.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "internal_msg_type.h"
#include <errno.h>
#include <arpa/inet.h>
#include <assert.h>
#include "util.h"


#define RECV_BUF_SIZE 1024

static uint64_t seed0 = 0x1234567887654321;
static uint64_t seed1 = 0x8765432112345678;
static char cli_version = 1;


static proc_result_t *errhndl_ignore(void *ctx, void *payload, uint16_t payload_size)
{
    rpc_event_loop *loop = (rpc_event_loop *)ctx;
    printf("receive err msg 0x%04x, ignore it\n", loop->recvd_msg_type);
    return NULL;
}

static proc_result_t *errhndl_abort(void *ctx, void *payload, uint16_t payload_size)
{
    rpc_event_loop *loop = (rpc_event_loop *)ctx;
    printf("receive err msg 0x%04x, abort\n", loop->recvd_msg_type);
    exit(-1);
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
        .proc_func = errhndl_abort,
        .free_func = NULL,
    },
    {
        .name = "RPC_SYS_ERR_UNKNOWN_MSG",
        .in_msg_type = RPC_SYS_ERR_UNKNOWN_MSG, 
        .in_payload_size = 0, 
        .in_check_func = NULL,
        .proc_func = errhndl_ignore,
        .free_func = NULL,
    },
    {
        .name = "RPC_SYS_ERR_VERSION",
        .in_msg_type = RPC_SYS_ERR_VERSION, 
        .in_payload_size = 0, 
        .in_check_func = NULL, 
        .proc_func = errhndl_abort,
        .free_func = NULL,
    },
    {
        .name = "RPC_SYS_ERR_INTERNAL",
        .in_msg_type = RPC_SYS_ERR_INTERNAL, 
        .in_payload_size = 0, 
        .in_check_func = NULL, 
        .proc_func = errhndl_ignore,
        .free_func = NULL,
    },
    {
        .name = "RPC_SYS_ERR_PAYLOAD_CHECK",
        .in_msg_type = RPC_SYS_ERR_PAYLOAD_CHECK, 
        .in_payload_size = 0, 
        .in_check_func = NULL,
        .proc_func = errhndl_ignore,
        .free_func = NULL,
    },
    {
        .name = "RPC_SYS_ERR_UNKNOWN",
        .in_msg_type = RPC_SYS_ERR_UNKNOWN, 
        .in_payload_size = 0, 
        .in_check_func = NULL, 
        .proc_func = errhndl_ignore,
        .free_func = NULL,
    },
};

int register_msg_handler(rpc_client_t *client, msg_handler_t *r)
{   
    assert(r->in_msg_type && is_allowed_msg(r->in_msg_type));
    if (r->out_msg_type) {
        assert(is_allowed_msg(r->out_msg_type));
    }
    assert(hashmap_get(client->hndls, &(msg_handler_t){.in_msg_type = r->in_msg_type}) == NULL);
    hashmap_set(client->hndls, (const void *)r);

    return 0;
}

static msg_handler_t *search_rpc(rpc_client_t *c, uint16_t msg_type) {
    return (msg_handler_t *)hashmap_get(c->hndls, &(msg_handler_t){.in_msg_type = msg_type});
}

void rpc_client_set_disconnect_cb(rpc_client_t *c, disconnect_cb cb)
{
    c->lp->on_disconnect = cb;
}

void rpc_client_set_connect_cb(rpc_client_t *c, connect_cb cb)
{
    c->lp->on_connect = cb;
}

int rpc_client_enable_keepalive(rpc_client_t *c)
{
    c->enable_keepalive = 1;
    int i;
    for (i = 0; i < sizeof(heartbeat_hndls) / sizeof(heartbeat_hndls[0]); i++) {
        hashmap_set(c->hndls, (const void *)&heartbeat_hndls[i]);
    }

    return 0;
}

rpc_client_t *new_rpc_client(char *ip, uint16_t port)
{
    rpc_client_t *c = (rpc_client_t *)malloc(sizeof(rpc_client_t));
    memset(c, 0, sizeof(rpc_client_t));
    strcpy(c->server_addr, ip);
    c->server_port = port;
    c->hndls = hashmap_new(sizeof(msg_handler_t), 0, seed0, seed1, 
                                     rpc_hash, rpc_compare, NULL, NULL);
    pthread_mutex_init(&c->lock, NULL);
    c->lp = (rpc_event_loop *)malloc(sizeof(rpc_event_loop));
    c->enable_keepalive = 0;
    memset(c->lp, 0, sizeof(rpc_event_loop));
    c->lp->conn_status = RPC_CONNECTION_STATUS_DISCONNECTED;
    c->lp->sock_fd = -1;
    strcpy(c->lp->peer_ip, c->server_addr);
    c->lp->peer_port = c->server_port;
    c->lp->in_header = malloc(sizeof(struct msg_header_t));
    c->lp->in_body = malloc(65535);
    c->lp->recv_buf = malloc(RECV_BUF_SIZE);
    c->lp->out_msg_buf = malloc(sizeof(fifo));
    c->lp->seq = ATOMIC_VAR_INIT(0);
    c->status = ATOMIC_VAR_INIT(0);
    fifo_init(c->lp->out_msg_buf, free);

    int i;
    for (i = 0; i < sizeof(err_hndls) / sizeof(err_hndls[0]); i++) {
        hashmap_set(c->hndls, (const void *)&err_hndls[i]);
    }

    return c;
}

static void do_send(rpc_event_loop *loop)
{
    while (1) {
        if (fifo_empty(loop->out_msg_buf)) {
            break;
        }
        
        rpc_buf_t *msg = fifo_pop(loop->out_msg_buf);
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
            printf("need close, stop sending data\n");
            break;
        }
    }
}

static void send_msg_now(rpc_event_loop *loop, uint16_t msg_type, void *payload, uint16_t payload_size) 
{
    int msg_size = sizeof(struct msg_t) + payload_size;
    struct msg_t *msg = malloc(msg_size);
    msg->header.magic_number = htonl(RPC_MAGIC_NUMBER);
    msg->header.version = cli_version;
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
            if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                loop->close_conn = 1;
                break;
            }
            continue;
        }
        sent += ret;
    }
    free(msg);
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
        printf("magic_number not match\n");
        send_err_msg(loop, RPC_SYS_ERR_MAGIC_NUMBER, 0);
        return -1;
    }

    char version = header->version;
    if (version != cli_version) {
        printf("version not match, server_version:%d, msg_version: %d\n", cli_version, version);
        send_err_msg(loop, RPC_SYS_ERR_VERSION, 0);
        return -1;
    }

    uint16_t msg_type = ntohs(header->msg_type);
    if (msg_type == 0) {
        printf("message type can not be 0\n");
        send_err_msg(loop, RPC_SYS_ERR_UNKNOWN_MSG, 0);
        return -1;
    }

    printf("recvd msg type: 0x%04x\n", ntohs(header->msg_type));
    return 0;
}

static void do_process(rpc_client_t *c, rpc_event_loop *loop)
{
    proc_result_t *out = NULL;

    printf("recvd msg type: 0x%04x, msg_seq: %d, payload_size: %d\n", loop->recvd_msg_type, loop->recvd_msg_seq, loop->in_body_size);
    const msg_handler_t *r = search_rpc(c, loop->recvd_msg_type);
    if (r == NULL) {
        printf("unknown message type 0x%04x\n", loop->recvd_msg_type);
        send_err_msg(loop, RPC_SYS_ERR_UNKNOWN_MSG, 0);
        goto reset_ev;
    }

    if (r->in_check_func && r->in_check_func((void *)r, loop->in_body, loop->in_body_size)) {
        printf("payload check failed. msg_seq: %d, payload_size:%d \n", loop->recvd_msg_seq, loop->in_body_size);
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

static void do_recv(rpc_client_t *c)
{
    rpc_event_loop *loop = c->lp;
    int header_len = sizeof(struct msg_header_t);
    char *buf = loop->recv_buf;

    int recvd = recv(loop->sock_fd, buf, RECV_BUF_SIZE, 0);
    if (recvd == 0) {
        loop->conn_status = RPC_CONNECTION_STATUS_DISCONNECTED;
        return;
    }
    if (recvd < 0) {
        return;
    }
    
    int left = recvd;

    while (left > 0) {
        if (loop->status == EL_NORMAL) {
            if (left >= header_len) {
                struct msg_header_t *h = (struct msg_header_t *)(buf + recvd - left);
                if (check_header(loop, h) != 0) {
                    loop->close_conn = 1;
                    break;
                }
                left -= header_len;
                loop->recvd_msg_type = ntohs(h->msg_type);
                loop->recvd_msg_seq = ntohs(h->msg_seq);
                loop->in_body_size = ntohs(h->payload_size);
                loop->msg_header = (void *)h;
                if (loop->in_body_size == 0) {
                    do_process(c, loop);
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
                loop->close_conn = 1;
                break;
            }
            loop->in_body_size = ntohs(h->payload_size);
            loop->recvd_msg_type = ntohs(h->msg_type);
            loop->recvd_msg_seq = ntohs(h->msg_seq);
            loop->msg_header = (void *)h;
            if (loop->in_body_size == 0) {
                do_process(c, loop);
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
            do_process(c, loop);
            left -= wait_body;
            continue;
        }
    }
}

static void *rpc_client(void *arg)
{
    rpc_client_t *c = (rpc_client_t *)arg;
    fd_set rfds, wfds;

    while (1) {
        FD_ZERO(&wfds);
        FD_ZERO(&rfds);
        
        if (atomic_load(&c->status) == 0) {
            printf("stopping rpc client\n");
            break;
        }

        if (c->lp->conn_status == RPC_CONNECTION_STATUS_DISCONNECTED) {
            if (c->lp->sock_fd > 0) {
                if (c->lp->on_disconnect) {
                    c->lp->on_disconnect(c->lp);
                }
                closesocket(c->lp->sock_fd);
                c->lp->close_conn = 0;
                c->lp->sock_fd = -1;
                c->lp->status = EL_NORMAL;
                c->lp->recvd_in_body = 0;
                c->lp->recvd_in_header = 0;
                c->lp->recvd_msg_type = 0;
                c->lp->in_body_size = 0;
            }
            printf("connection to %s:%d closed, try connect\n", c->lp->peer_ip, c->lp->peer_port);
            int new_sockfd = socket(AF_INET, SOCK_STREAM, 0);  
            if (new_sockfd < 0) {
                printf("socket error\n");
                usleep(500000);
                continue;
            }
            struct sockaddr_in server_addr;
            server_addr.sin_family = AF_INET;
            server_addr.sin_port = htons(c->server_port);
            inet_pton(AF_INET, c->server_addr, &server_addr.sin_addr);
            int connresult = connect(new_sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr));
            if (connresult != 0) {
                printf("connect server error\n");
                closesocket(new_sockfd);
                usleep(500000);
                continue;
            }
            printf("new connection established\n");
            c->lp->sock_fd = new_sockfd;
            c->lp->conn_status = RPC_CONNECTION_STATUS_CONNECTED;
            c->lp->close_conn = 0;
            c->lp->recv_heartbeat_time = ATOMIC_VAR_INIT(0);
            c->lp->send_heartbeat_time = get_time_ms();
            atomic_store(&c->lp->recv_heartbeat_time, c->lp->send_heartbeat_time);
            if (c->lp->on_connect) {
                c->lp->on_connect(c->lp);
            }
            continue;
        }

        int sock = c->lp->sock_fd;


        if (c->enable_keepalive) {
            uint64_t time_ms = get_time_ms();

            if (time_ms > c->lp->send_heartbeat_time + 1000) {
                send_msg(c, RPC_SYS_HEARTBEAT_REQ, NULL, 0);
                c->lp->send_heartbeat_time = time_ms;
            }

            if (time_ms > atomic_load(&c->lp->recv_heartbeat_time) + 3000) {
                printf("heartbeat timeout\n");
                c->lp->close_conn = 1;
                goto check_status;
            }
        }

        int need_send = !fifo_empty(c->lp->out_msg_buf);

        FD_SET(sock, &rfds);
        if (need_send) {
            FD_SET(sock, &wfds);
        }

        struct timeval tv = {.tv_sec = 0, .tv_usec = 10000};
        int retval;
        if (need_send) {
            retval = select(sock + 1, &rfds, &wfds, NULL, &tv);
        } else {
            retval = select(sock + 1, &rfds, NULL, NULL, &tv);
        }

        if (retval < 0) {
            printf("select failed\n");
            continue;
        }

        if (retval == 0){
            continue;
        }

        if (need_send && FD_ISSET(sock, &wfds)) {
            do_send(c->lp);
        }

        if (FD_ISSET(sock, &rfds)) {
            do_recv(c);
        }

        check_status:
        if (c->lp->close_conn) {
            c->lp->conn_status = RPC_CONNECTION_STATUS_DISCONNECTED;
        }
    }


    if (c->lp->sock_fd > 0) {
        closesocket(c->lp->sock_fd);
        if (c->lp->on_disconnect) {
            c->lp->on_disconnect(c->lp);
        }
    }

    hashmap_free(c->hndls);
    free(c->lp->in_header);
    free(c->lp->in_body);
    free(c->lp->recv_buf);
    fifo_destroy(c->lp->out_msg_buf);
    free(c->lp->out_msg_buf);
    free(c->lp);
    printf("rpc client stopped\n");

    ret_value = 0;
    pthread_exit(&ret_value);
}

int start_rpc_client(rpc_client_t *c)
{
    pthread_mutex_lock(&c->lock);
    if (atomic_load(&c->status) == 0) {
        atomic_store(&c->status, 1);
    } else {
        printf("rpc client already started\n");
        pthread_mutex_unlock(&c->lock);
        return 0;
    }
    pthread_mutex_unlock(&c->lock);
    
    size_t iter = 0;
    void *item;
    while (hashmap_iter(c->hndls, &iter, &item)) {
        const msg_handler_t *hndl = (const msg_handler_t *)item;
        if (hndl->in_msg_type >> 8) {
            printf("handler %s registered\n", hndl->name);
        }
    }

    pthread_t pthreadId;
	int ret = pthread_create(&pthreadId, NULL, rpc_client, c);
    if (ret != 0) {
        printf("create rpc client thread failed\n");
        return -1;
    }
    c->tid = pthreadId;

    return 0;
}

int stop_rpc_client(rpc_client_t *c)
{
    if (c == NULL) {
        return 0;
    }

    atomic_store(&c->status, 0);
    int *retval;
    pthread_join(c->tid, (void **)&retval);
    if (*retval != 0) {
        printf("rpc client thread exit with error %d\n", *retval);
    }
    pthrea_mutex_destroy(&c->lock);
    free(c);
    printf("rpc client destroyed\n");

    return 0;
}

int send_msg(const rpc_client_t *c, uint16_t msg_type, void *payload, uint16_t payload_size)
{
    rpc_event_loop *loop = c->lp;
    rpc_buf_t *buf = malloc(sizeof(rpc_buf_t));

    int msg_size = sizeof(struct msg_t) + payload_size;
    struct msg_t *msg = malloc(msg_size);
    msg->header.magic_number = htonl(RPC_MAGIC_NUMBER);
    msg->header.version = cli_version;
    msg->header.msg_source = 0;
    msg->header.msg_dest = 0;
    msg->header.msg_type = htons(msg_type);
    msg->header.payload_size = htons(payload_size);
    msg->header.msg_seq = htons(atomic_fetch_add(&loop->seq, 1));

    if (payload_size > 0 && payload != NULL) {
        memcpy(msg->data, payload, payload_size);
    }

    buf->data = (void *)msg;
    buf->data_size = msg_size;
    buf->close_after = 0;
    buf->offset = 0;

    fifo_push(loop->out_msg_buf, (void *)buf);
    return 0;
}