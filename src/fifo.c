/*
 * File: fifo.c
 * File Created: Tuesday, 11th June 2024 6:39:24 pm
 * Author: qiuhui (qiuhui@leelen.com)
 * -----
 * Last Modified: Tuesday, 11th June 2024 6:39:29 pm
 * Modified By: qiuhui (qiuhui@leelen.com>)
 * -----
 * Copyright - 2024 leelen, leelen
 */

#include "fifo.h"
#include <string.h>

void fifo_init(fifo *queue, free_func free) 
{  
    queue->head = 0;
    queue->tail = 0;  
    queue->count = 0;  
    queue->free = free;
    memset(queue->data, 0, sizeof(queue->data));
    pthread_mutex_init(&queue->lock, NULL);
    pthread_cond_init(&queue->not_empty, NULL);
    pthread_cond_init(&queue->not_full, NULL); 
}
  
void fifo_push(fifo *queue, void *value) 
{  
    pthread_mutex_lock(&queue->lock);
    while (queue->count == QUEUE_SIZE) {
        pthread_cond_wait(&queue->not_full, &queue->lock);
    }
    queue->data[queue->tail] = value;
    queue->tail = (queue->tail + 1) % QUEUE_SIZE;
    queue->count++;
    pthread_cond_signal(&queue->not_empty);
    pthread_mutex_unlock(&queue->lock);
}  
  
void *fifo_pop(fifo *queue) 
{
    pthread_mutex_lock(&queue->lock);  
    while (queue->count == 0) {  
        pthread_cond_wait(&queue->not_empty, &queue->lock);  
    }  
    void *value = queue->data[queue->head]; 
    queue->data[queue->head] = NULL;
    queue->head = (queue->head + 1) % QUEUE_SIZE;  
    queue->count--;
    pthread_cond_signal(&queue->not_full);
    pthread_mutex_unlock(&queue->lock);
    return value;
} 

int fifo_empty(fifo *queue) 
{
    int count = 0;
    pthread_mutex_lock(&queue->lock);  
    count = queue->count;
    pthread_mutex_unlock(&queue->lock);
    return count == 0;  
}

int fifo_full(fifo *queue) 
{
    int count = 0;
    pthread_mutex_lock(&queue->lock);  
    count = queue->count;
    pthread_mutex_unlock(&queue->lock);
    return count == QUEUE_SIZE;  
}

void fifo_destroy(fifo *queue) 
{   
    for (int i = 0; i < QUEUE_SIZE; i++) {
        if (queue->free && queue->data[i] != NULL) {
            queue->free(queue->data[i]);
        }
    }
    pthread_mutex_destroy(&queue->lock);  
    pthread_cond_destroy(&queue->not_empty);  
    pthread_cond_destroy(&queue->not_full);  
}