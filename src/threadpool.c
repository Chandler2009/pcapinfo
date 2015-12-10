//
// Created by Julien Fortin on 12/8/15.
//

#include <stddef.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <strings.h>

#include "threadpool.h"

char _pthread_mutex_lock(pthread_mutex_t* mutex)
{
    if (pthread_mutex_lock(mutex))
    {
        perror("pthread_mutex_lock");
        return 0;
    }
    return 1;
}

char _pthread_mutex_unlock(pthread_mutex_t* mutex)
{
    if (pthread_mutex_unlock(mutex))
    {
        perror("pthread_mutex_unlock");
        return 0;
    }
    return 1;
}

static void*   _threadpool_thread(void *data)
{
    if (!data) return NULL;

    threadpool_t*   pool = (threadpool_t*)data;
    tasks_t         task;

    while (42)
    {
        if (!_pthread_mutex_lock(&pool->pool_lock))
            break;
        while (pool->queue->count == 0 && pool->status == THREADPOOL_STATUS_OK)
            if (pthread_cond_wait(&pool->notify_cond, &pool->pool_lock))
            {
                _pthread_mutex_unlock(&pool->pool_lock);
                perror("pthread_cond_wait");
                break;
            }

        if (pool->status == THREADPOOL_STATUS_STOP && pool->queue->count == 0)
        {
            _pthread_mutex_unlock(&pool->pool_lock);
            break;
        }

        if (pool->queue->count > 0)
        {
            if (pool->queue->tail >= pool->queue->size)
                pool->queue->tail = 0;

            bzero(&task, sizeof(tasks_t));

            task.function = pool->queue->tasks[pool->queue->tail].function;
            task.data = pool->queue->tasks[pool->queue->tail].data;
            bzero(&pool->queue->tasks[pool->queue->tail++], sizeof(tasks_t));
            pool->queue->count--;
        }

        if (!_pthread_mutex_unlock(&pool->pool_lock))
            break;

        if (task.function)
            task.function(task.data);
    }
    pthread_exit(NULL);
    return NULL;
}

static void*    _thread_pool_error(threadpool_t* pool, const char* str)
{
    if (str)
        perror(str);
    threadpool_delete(pool);
    return NULL;
}

static int _thread_pool_add_thread(threadpool_t* pool, thread_t* thread)
{
    if (pthread_create(&thread->thread, NULL, &_threadpool_thread, (void*)pool))
    {
        _thread_pool_error(pool, "pthread_create");
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

static int _thread_pool_new_workers(threadpool_t* pool)
{
    for (size_t i = 0; i < pool->size; ++i)
        if ((_thread_pool_add_thread(pool, &pool->threads[i])) == EXIT_FAILURE)
            return EXIT_FAILURE;
    return EXIT_SUCCESS;
}

static task_queue_t*    _thread_pool_new_queue(threadpool_t* pool, size_t queue_size)
{
    pool->queue = calloc(1, sizeof(task_queue_t));

    if (!pool->queue)
        return _thread_pool_error(pool, "queue calloc");

    pool->queue->size = queue_size;
    pool->queue->tasks = calloc(pool->queue->size, sizeof(tasks_t));
    pool->queue->head = pool->queue->tail = pool->queue->count = 0;

    if (!pool->queue->tasks)
        return _thread_pool_error(pool, "tasks calloc");

    return pool->queue;
}

threadpool_t*   threadpool_new(size_t pool_size, size_t queue_size)
{
    threadpool_t*   pool;

    if (!(pool = calloc(1, sizeof(threadpool_t))))
        return _thread_pool_error(pool, "pool calloc");
    if (!(pool->threads = calloc(pool_size + 1, sizeof(thread_t))))
        return _thread_pool_error(pool, "threads calloc");

    pool->size = pool_size;
    pool->status = THREADPOOL_STATUS_OK;

    if (!_thread_pool_new_queue(pool, queue_size))
        return NULL;

    if (pthread_mutex_init(&pool->pool_lock, NULL))
        return _thread_pool_error(pool, "lock pthread_mutex_init");

    if (pthread_cond_init(&pool->notify_cond, NULL))
        return _thread_pool_error(pool, "cond pthread_cond_init");

    return _thread_pool_new_workers(pool) != EXIT_FAILURE ? pool : NULL;
}

int threadpool_add_task(threadpool_t* pool, void* (*task)(void*), void* data)
{
    if (!pool || !task)
        return EXIT_FAILURE;
    if (!_pthread_mutex_lock(&pool->pool_lock))
        return EXIT_FAILURE;
    if (pool->queue->count >= pool->queue->size)
    {
        _pthread_mutex_unlock(&pool->pool_lock);
        return EXIT_FAILURE;
    }

    if (pool->queue->head >= pool->queue->size)
        pool->queue->head = 0;

    pool->queue->tasks[pool->queue->head].function = task;
    pool->queue->tasks[pool->queue->head++].data = data;

    pool->queue->count++;

    if (pthread_cond_broadcast(&pool->notify_cond))
    {
        perror("add task pthread_cond_broadcast");
        return EXIT_FAILURE;
    }
    if (!_pthread_mutex_unlock(&pool->pool_lock))
        return EXIT_FAILURE;
    return EXIT_SUCCESS;
}

static void _threadpool_free(threadpool_t* pool)
{
    free(pool->threads);
    if (pthread_mutex_destroy(&pool->pool_lock))
        perror("notify pthread_mutex_destroy");
    if (pthread_cond_destroy(&pool->notify_cond))
        perror("pthread_cond_destroy");
    if (pool->queue)
    {
        free(pool->queue->tasks);
        free(pool->queue);
    }
    free(pool);
}

void threadpool_delete(threadpool_t* pool)
{
    if (pool)
    {
        if (pool->threads && _pthread_mutex_lock(&pool->pool_lock))
        {
            pool->status = THREADPOOL_STATUS_STOP;
            if (pthread_cond_broadcast(&pool->notify_cond))
                perror("pthread_cond_broadcast");
            else
            {
                _pthread_mutex_unlock(&pool->pool_lock);
                for (size_t i = 0; i < pool->size; ++i)
                    if (pthread_join(pool->threads[i].thread, NULL))
                        perror("pthread_join");
            }
        }
        _threadpool_free(pool);
    }
}
