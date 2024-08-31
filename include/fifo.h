/*
 * File: fifo.h
 * File Created: Tuesday, 11th June 2024 6:40:21 pm
 * Author: qiuhui (qiuhui@leelen.com)
 * -----
 * Last Modified: Tuesday, 11th June 2024 6:40:31 pm
 * Modified By: qiuhui (qiuhui@leelen.com>)
 * -----
 * Copyright - 2024 leelen, leelen
 */

#ifndef __FIFO_H__
#define __FIFO_H__

#include <stdio.h>  
#include <stdlib.h>   
#include <pthread.h>  
#include <stdbool.h>  

#if defined(__cplusplus)
extern "C" {
#endif  // __cplusplus


#define QUEUE_SIZE 10  

typedef void (*free_func)(void *data);

typedef struct {  
    void *data[QUEUE_SIZE];  
    size_t head;  
    size_t tail;  
    size_t count;  
    pthread_mutex_t lock;
    pthread_cond_t  not_empty;  
    pthread_cond_t  not_full;
    free_func free;
} fifo;  


void fifo_init(fifo *queue, free_func free);
  
void fifo_push(fifo *queue, void *value);
  
void *fifo_pop(fifo *queue);

int fifo_empty(fifo *queue);

int fifo_full(fifo *queue);

void fifo_destroy(fifo *queue);

#if defined(__cplusplus)
}
#endif  // __cplusplus

#endif 