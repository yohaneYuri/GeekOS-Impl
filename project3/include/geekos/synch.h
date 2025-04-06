/*
 * Synchronization primitives
 * Copyright (c) 2001, David H. Hovemeyer <daveho@cs.umd.edu>
 * $Revision: 1.13 $
 * 
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "COPYING".
 */

#ifndef GEEKOS_SYNCH_H
#define GEEKOS_SYNCH_H

#include <geekos/kthread.h>

/*
 * mutex states
 */
enum { MUTEX_UNLOCKED, MUTEX_LOCKED };

struct Mutex {
    int state;
    struct Kernel_Thread* owner;
    struct Thread_Queue waitQueue;
};

#define MUTEX_INITIALIZER { MUTEX_UNLOCKED, 0, THREAD_QUEUE_INITIALIZER }

struct Condition {
    struct Thread_Queue waitQueue;
};

void Mutex_Init(struct Mutex* mutex);
void Mutex_Lock(struct Mutex* mutex);
void Mutex_Unlock(struct Mutex* mutex);

void Cond_Init(struct Condition* cond);
void Cond_Wait(struct Condition* cond, struct Mutex* mutex);
void Cond_Signal(struct Condition* cond);
void Cond_Broadcast(struct Condition* cond);

#define IS_HELD(mutex) \
    ((mutex)->state == MUTEX_LOCKED && (mutex)->owner == g_currentThread)


#define MAX_SEMAPHORE_NAME_LEN 25
struct Semaphore {
    bool available;
    char name[MAX_SEMAPHORE_NAME_LEN + 1]; // What's the usage of you?
    uchar_t nameLen;
    int resource;
    struct Thread_Queue waitQueue;
    uint_t refCount;
};

#define MAX_SEMAPHORE_NUM 32
extern struct Semaphore g_allSemaphores[MAX_SEMAPHORE_NUM];

int Init_Semaphore(char *name, uchar_t nameLen, int resource);
int Semaphore_Acquire(uint_t id);
int Semaphore_Release(uint_t id);
int Destroy_Semaphore(uint_t id);
void Register_Semaphore(uint_t id);

#endif  /* GEEKOS_SYNCH_H */
