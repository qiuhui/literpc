/*
 * File: event_loop.c
 * File Created: Thursday, 6th June 2024 6:30:13 pm
 * Author: qiuhui (qiuhui@leelen.com)
 * -----
 * Last Modified: Thursday, 6th June 2024 6:30:15 pm
 * Modified By: qiuhui (qiuhui@leelen.com>)
 * -----
 * Copyright - 2024 leelen, leelen
 */

#include "event_loop.h"
#include <stdlib.h>

rpc_event_loop_node *create_rpc_event_loop(rpc_event_loop *loop)
{
    rpc_event_loop_node *newNode = (rpc_event_loop_node *)malloc(sizeof(rpc_event_loop_node));
    if (newNode == NULL) {
        return NULL;
    }
    newNode->data = loop;
    newNode->next = NULL;
    return newNode;
}

void insert_rpc_event_loop(rpc_event_loop_node **head, rpc_event_loop *loop)
{
    rpc_event_loop_node* newNode = create_rpc_event_loop(loop);
    newNode->next = *head;
    *head = newNode;
}

void delete_rpc_event_loop(rpc_event_loop_node **head, rpc_event_loop *loop)
{
    rpc_event_loop_node *temp = *head;
    if (temp == NULL) {
        return;
    }

    if (temp != NULL && temp->data == loop) {
        *head = temp->next;
        free(temp);
        return;
    }
    while (temp != NULL && temp->next != NULL && temp->next->data != loop) {
        temp = temp->next;
    }
    if (temp->next != NULL && temp->next->data == loop) {
        rpc_event_loop_node *toDelete = temp->next;
        temp->next = toDelete->next;
        free(toDelete);
    }
}