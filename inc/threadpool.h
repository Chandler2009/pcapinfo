//
// Created by Julien Fortin on 12/8/15.
//

#ifndef __THREADPOOL_H__
#define __THREADPOOL_H__

#include <pthread.h>

typedef struct thread_s
{
    pthread_t   thread;
} thread_t;

typedef struct tasks_s
{
    void*   data;
    void*   (*function)(void*);
} tasks_t;

typedef struct task_queue_s
{
    tasks_t *tasks;
    size_t  head;
    size_t  tail;
    size_t  count;
    size_t  size;
} task_queue_t;

typedef struct threadpool_s
{
    thread_t*       threads;
    task_queue_t*   queue;
    size_t          size;
    char            status;
    pthread_mutex_t pool_lock;
    pthread_cond_t  notify_cond;
} threadpool_t;

#define THREADPOOL_STATUS_OK       0
#define THREADPOOL_STATUS_STOP     42

threadpool_t*   threadpool_new(size_t, size_t);
void            threadpool_delete(threadpool_t*);
int threadpool_add_task(threadpool_t*, void* (*)(void*), void*);

char _pthread_mutex_lock(pthread_mutex_t*);
char _pthread_mutex_unlock(pthread_mutex_t*);

#endif