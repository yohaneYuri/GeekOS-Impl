/*
 * Synchronization primitives
 * Copyright (c) 2001,2004 David H. Hovemeyer <daveho@cs.umd.edu>
 * $Revision: 1.13 $
 * 
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "COPYING".
 */

#include <geekos/kthread.h>
#include <geekos/int.h>
#include <geekos/kassert.h>
#include <geekos/screen.h>
#include <geekos/synch.h>
#include <geekos/string.h>

/*
 * NOTES:
 * - The GeekOS mutex and condition variable APIs are based on those
 *   in pthreads.
 * - Unlike disabling interrupts, mutexes offer NO protection against
 *   concurrent execution of interrupt handlers.  Mutexes and
 *   condition variables should only be used from kernel threads,
 *   with interrupts enabled.
 */

volatile static uchar_t s_availableSemaphoresNum = MAX_SEMAPHORE_NUM;
struct Semaphore g_allSemaphores[MAX_SEMAPHORE_NUM];

/* ----------------------------------------------------------------------
 * Private functions
 * ---------------------------------------------------------------------- */

/*
 * The mutex is currently locked.
 * Atomically reenable preemption and wait in the
 * mutex's wait queue.
 */
static void Mutex_Wait(struct Mutex *mutex)
{
    KASSERT(mutex->state == MUTEX_LOCKED);
    KASSERT(g_preemptionDisabled);

    Disable_Interrupts();
    g_preemptionDisabled = false;
    Wait(&mutex->waitQueue);
    g_preemptionDisabled = true;
    Enable_Interrupts();
}

/*
 * Lock given mutex.
 * Preemption must be disabled.
 */
static __inline__ void Mutex_Lock_Imp(struct Mutex* mutex)
{
    KASSERT(g_preemptionDisabled);

    /* Make sure we're not already holding the mutex */
    KASSERT(!IS_HELD(mutex));

    /* Wait until the mutex is in an unlocked state */
    while (mutex->state == MUTEX_LOCKED) {
	Mutex_Wait(mutex);
    }

    /* Now it's ours! */
    mutex->state = MUTEX_LOCKED;
    mutex->owner = g_currentThread;
}

/*
 * Unlock given mutex.
 * Preemption must be disabled.
 */
static __inline__ void Mutex_Unlock_Imp(struct Mutex* mutex)
{
    KASSERT(g_preemptionDisabled);

    /* Make sure mutex was actually acquired by this thread. */
    KASSERT(IS_HELD(mutex));

    /* Unlock the mutex. */
    mutex->state = MUTEX_UNLOCKED;
    mutex->owner = 0;

    /*
     * If there are threads waiting to acquire the mutex,
     * wake one of them up.  Note that it is legal to inspect
     * the queue with interrupts enabled because preemption
     * is disabled, and therefore we know that no thread can
     * concurrently add itself to the queue.
     */
    if (!Is_Thread_Queue_Empty(&mutex->waitQueue)) {
        Disable_Interrupts();
        Wake_Up_One(&mutex->waitQueue);
        Enable_Interrupts();
    }
}

/**
 * Returns available id, otherwise return -1
 */
static __inline__ int Find_Available_Semaphore(void) {
    if (s_availableSemaphoresNum == 0) {
        return -1;
    }

    int id = 0;
    for (; id < MAX_SEMAPHORE_NUM; ++id) {
        if (!g_allSemaphores[id].available) {
            g_allSemaphores[id].available = true;
            return id;
        }
    }
    KASSERT(false);
}

/**
 * Returns semaphore id when successed, ohterwise -1
 */
static __inline__ int Find_Semaphore_By_Name(char *name, uchar_t nameLen) {
    KASSERT(name != 0 && nameLen != 0);

    for (int i = 0; i < MAX_SEMAPHORE_NUM; ++i) {
        if (g_allSemaphores[i].available)
        {
            if (strncmp(g_allSemaphores[i].name, name, nameLen) == 0) {
                return i;
            }
        }
    }

    return -1;
}

/* ----------------------------------------------------------------------
 * Public functions
 * ---------------------------------------------------------------------- */

/*
 * Initialize given mutex.
 */
void Mutex_Init(struct Mutex* mutex)
{
    mutex->state = MUTEX_UNLOCKED;
    mutex->owner = 0;
    Clear_Thread_Queue(&mutex->waitQueue);
}

/*
 * Lock given mutex.
 */
void Mutex_Lock(struct Mutex* mutex)
{
    KASSERT(Interrupts_Enabled());

    g_preemptionDisabled = true;
    Mutex_Lock_Imp(mutex);
    g_preemptionDisabled = false;
}

/*
 * Unlock given mutex.
 */
void Mutex_Unlock(struct Mutex* mutex)
{
    KASSERT(Interrupts_Enabled());

    g_preemptionDisabled = true;
    Mutex_Unlock_Imp(mutex);
    g_preemptionDisabled = false;
}

/*
 * Initialize given condition.
 */
void Cond_Init(struct Condition* cond)
{
    Clear_Thread_Queue(&cond->waitQueue);
}

/*
 * Wait on given condition (protected by given mutex).
 */
void Cond_Wait(struct Condition* cond, struct Mutex* mutex)
{
    KASSERT(Interrupts_Enabled());

    /* Ensure mutex is held. */
    KASSERT(IS_HELD(mutex));

    /* Turn off scheduling. */
    g_preemptionDisabled = true;

    /*
     * Release the mutex, but leave preemption disabled.
     * No other threads will be able to run before this thread
     * is able to wait.  Therefore, this thread will not
     * miss the eventual notification on the condition.
     */
    Mutex_Unlock_Imp(mutex);

    /*
     * Atomically reenable preemption and wait in the condition wait queue.
     * Other threads can run while this thread is waiting,
     * and eventually one of them will call Cond_Signal() or Cond_Broadcast()
     * to wake up this thread.
     * On wakeup, disable preemption again.
     */
    Disable_Interrupts();
    g_preemptionDisabled = false;
    Wait(&cond->waitQueue);
    g_preemptionDisabled = true;
    Enable_Interrupts();

    /* Reacquire the mutex. */
    Mutex_Lock_Imp(mutex);

    /* Turn scheduling back on. */
    g_preemptionDisabled = false;
}

/*
 * Wake up one thread waiting on the given condition.
 * The mutex guarding the condition should be held!
 */
void Cond_Signal(struct Condition* cond)
{
    KASSERT(Interrupts_Enabled());
    Disable_Interrupts();  /* prevent scheduling */
    Wake_Up_One(&cond->waitQueue);
    Enable_Interrupts();  /* resume scheduling */
}

/*
 * Wake up all threads waiting on the given condition.
 * The mutex guarding the condition should be held!
 */
void Cond_Broadcast(struct Condition* cond)
{
    KASSERT(Interrupts_Enabled());
    Disable_Interrupts();  /* prevent scheduling */
    Wake_Up(&cond->waitQueue);
    Enable_Interrupts();  /* resume scheduling */
}

// Code like poem, but like shit more in fact

/**
 * Returns available id, otherwise, -1 when no available semaphores,
 * -2 when arguments invalid
 */
int Init_Semaphore(char *name, uchar_t nameLen, int resource) {

    int id;

    if (name == 0 || nameLen == 0) {
        return -2;
    }

    id = Find_Semaphore_By_Name(name, nameLen);
    if (id != -1) {
        ++g_allSemaphores[id].refCount;
        return id;
    }

    id = Find_Available_Semaphore();
    if (id < 0) {
        return -1;
    }
    memcpy(&g_allSemaphores[id].name, name, nameLen);
    g_allSemaphores[id].name[nameLen] = 0;
    g_allSemaphores[id].resource = resource;
    Clear_Thread_Queue(&g_allSemaphores[id].waitQueue);
    g_allSemaphores[id].refCount = 1;
    ++s_availableSemaphoresNum;

    return id;
}

/**
 * Returns 0 when successed, -1 when no such semaphore
 */
int Semaphore_Acquire(uint_t id) {
    if (id >= MAX_SEMAPHORE_NUM) {
        return -1;
    }

    struct Semaphore *target = &g_allSemaphores[id];
    bool intEnable = Interrupts_Enabled();

    if (!target->available) {
        return -1;
    }

    if (intEnable) {
        Disable_Interrupts();
    }
    while (target->resource <= 0) {
        Wait(&target->waitQueue);
    }
    --target->resource;
    if (intEnable) {
        Enable_Interrupts();
    }

    return 0;
}

/**
 * Returns 0 when successed, -1 when no such semaphore
 */
int Semaphore_Release(uint_t id) {
    if (id >= MAX_SEMAPHORE_NUM) {
        return -1;
    }

    struct Semaphore *target = &g_allSemaphores[id];
    bool intEnable = Interrupts_Enabled();

    if (!target->available) {
        return -1;
    }

    if (intEnable) {
        Disable_Interrupts();
    }
    ++target->resource;
    if (target->resource > 0) {
        Wake_Up_One(&target->waitQueue);
    }
    if (intEnable) {
        Enable_Interrupts();
    }

    return 0;
}

/**
 * Destroy a semaphore whose refCount is 0
 * Returns 0 when successed, otherwise -1
 */
int Destroy_Semaphore(uint_t id) {
    KASSERT(id < MAX_SEMAPHORE_NUM);

    struct Semaphore *target = &g_allSemaphores[id];

    if (target->refCount != 0) {
        return -1;
    }
    
    if (target->available) {
        target->available = false;
        --s_availableSemaphoresNum;
    }

    return 0;
}

void Register_Semaphore(uint_t id) {
    for (int i = 0; i < MAX_SEMAPHORES_REFS; ++i) {
        if (g_currentThread->semaphores[i] == id) {
            return;
        }
    }

    for (int i = 0; i < MAX_SEMAPHORES_REFS; ++i) {
        if (g_currentThread->semaphores[i] == REF_TO_NO_SEMAPHORE) {
            ++g_currentThread->registeredSemaphores;
            g_currentThread->semaphores[i] = id;
            break;
        }
    }
}