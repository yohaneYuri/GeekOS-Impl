/*
 * System call handlers
 * Copyright (c) 2003, Jeffrey K. Hollingsworth <hollings@cs.umd.edu>
 * Copyright (c) 2003,2004 David Hovemeyer <daveho@cs.umd.edu>
 * $Revision: 1.59 $
 * 
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "COPYING".
 */

#include <geekos/syscall.h>
#include <geekos/errno.h>
#include <geekos/kthread.h>
#include <geekos/int.h>
#include <geekos/elf.h>
#include <geekos/malloc.h>
#include <geekos/screen.h>
#include <geekos/keyboard.h>
#include <geekos/string.h>
#include <geekos/user.h>
#include <geekos/timer.h>
#include <geekos/vfs.h>
#include <geekos/synch.h>

/*
 * Null system call.
 * Does nothing except immediately return control back
 * to the interrupted user program.
 * Params:
 *  state - processor registers from user mode
 *
 * Returns:
 *   always returns the value 0 (zero)
 */
static int Sys_Null(struct Interrupt_State* state)
{
    return 0;
}

/*
 * Exit system call.
 * The interrupted user process is terminated.
 * Params:
 *   state->ebx - process exit code
 * Returns:
 *   Never returns to user mode!
 */
static int Sys_Exit(struct Interrupt_State* state)
{
    // TODO("Exit system call");

    Exit(state->ebx);

    KASSERT(false);
}

/*
 * Print a string to the console.
 * Params:
 *   state->ebx - user pointer of string to be printed
 *   state->ecx - number of characters to print
 * Returns: 0 if successful, -1 if not
 */
static int Sys_PrintString(struct Interrupt_State* state)
{
    // TODO("PrintString system call");

    uint_t bufLen = state->ecx;

    if (bufLen == 0) {
        return 0;
    }

    char buf[bufLen];

    if (!Copy_From_User(buf, state->ebx, bufLen)) {
        return -1;
    }
    Put_Buf(buf, bufLen);

    return 0;
}

/*
 * Get a single key press from the console.
 * Suspends the user process until a key press is available.
 * Params:
 *   state - processor registers from user mode
 * Returns: the key code
 */
static int Sys_GetKey(struct Interrupt_State* state)
{
    // TODO("GetKey system call");

    return Wait_For_Key();
}

/*
 * Set the current text attributes.
 * Params:
 *   state->ebx - character attributes to use
 * Returns: always returns 0
 */
static int Sys_SetAttr(struct Interrupt_State* state)
{
    // TODO("SetAttr system call");

    Set_Current_Attr(state->ebx);

    return 0;
}

/*
 * Get the current cursor position.
 * Params:
 *   state->ebx - pointer to user int where row value should be stored
 *   state->ecx - pointer to user int where column value should be stored
 * Returns: 0 if successful, -1 otherwise
 */
static int Sys_GetCursor(struct Interrupt_State* state)
{
    // TODO("GetCursor system call");

    int row, col;

    if (state->ebx == 0 || state->ecx == 0) {
        return -1;
    }
    Get_Cursor(&row, &col);
    if (!Copy_To_User(state->ebx, &row, sizeof(int)) ||
        !Copy_To_User(state->ecx, &col, sizeof(int)))
    {
        return -1;
    }

    return 0;
}

/*
 * Set the current cursor position.
 * Params:
 *   state->ebx - new row value
 *   state->ecx - new column value
 * Returns: 0 if successful, -1 otherwise
 */
static int Sys_PutCursor(struct Interrupt_State* state)
{
    // TODO("PutCursor system call");

    if (!Put_Cursor(state->ebx, state->ecx)) {
        return -1;
    }

    return 0;
}

/*
 * Create a new user process.
 * Params:
 *   state->ebx - user address of name of executable
 *   state->ecx - length of executable name
 *   state->edx - user address of command string
 *   state->esi - length of command string
 * Returns: pid of process if successful, error code (< 0) otherwise
 */
static int Sys_Spawn(struct Interrupt_State* state)
{
    // TODO("Spawn system call");

    if (state->ebx == 0 || state->edx == 0) {
        return EINVALID;
    }

    int pid;
    char path[state->ecx + 1];
    char cmd[state->esi + 1];

    if (!Copy_From_User(path, state->ebx, state->ecx)
        || !Copy_From_User(cmd, state->edx, state->esi))
    {
        return ENOMEM;
    }
    path[state->ecx] = 0;
    cmd[state->esi] = 0;

    Enable_Interrupts();
    pid = Spawn(path, cmd, NULL);
    Disable_Interrupts();

    return pid;
}

/*
 * Wait for a process to exit.
 * Params:
 *   state->ebx - pid of process to wait for
 * Returns: the exit code of the process,
 *   or error code (< 0) on error
 */
static int Sys_Wait(struct Interrupt_State* state)
{
    // TODO("Wait system call");

    struct Kernel_Thread *kthread = Lookup_Thread(state->ebx);
    int exitCode = 0;
    if (kthread == 0) {
        return EUNSPECIFIED;
    }

    Enable_Interrupts();
    exitCode = Join(kthread);
    Disable_Interrupts();

    return exitCode;
}

/*
 * Get pid (process id) of current thread.
 * Params:
 *   state - processor registers from user mode
 * Returns: the pid of the current thread
 */
static int Sys_GetPID(struct Interrupt_State* state)
{
    // TODO("GetPID system call");

    return g_currentThread->pid;
}

/*
 * Set the scheduling policy.
 * Params:
 *   state->ebx - policy,
 *   state->ecx - number of ticks in quantum
 * Returns: 0 if successful, -1 otherwise
 */
static int Sys_SetSchedulingPolicy(struct Interrupt_State* state)
{
    // TODO("SetSchedulingPolicy system call");

    uint_t policy = state->ebx, quantum = state->ecx;

    if (policy != SCHEDULING_RR && policy != SCHEDULING_MLFQ) {
        return -1;
    }

    if (policy != g_schedulingPolicy) {
        Move_Threads_To_0_Except_Idle();
        g_schedulingPolicy = policy;
    }

    g_Quantum = quantum;

    return 0;
}

/*
 * Get the time of day.
 * Params:
 *   state - processor registers from user mode
 *
 * Returns: value of the g_numTicks global variable
 */
static int Sys_GetTimeOfDay(struct Interrupt_State* state)
{
    // TODO("GetTimeOfDay system call");

    return g_numTicks;
}

/*
 * Create a semaphore.
 * Params:
 *   state->ebx - user address of name of semaphore
 *   state->ecx - length of semaphore name
 *   state->edx - initial semaphore count
 * Returns: the global semaphore id
 */
static int Sys_CreateSemaphore(struct Interrupt_State* state)
{
    // TODO("CreateSemaphore system call");

    if (g_currentThread->registeredSemaphores >= MAX_SEMAPHORES_REFS) {
        return -1;
    }

    uint_t nameUserAddr = state->ebx, nameLen = state->ecx, resource = state->edx;
    int id;

    if (nameUserAddr == 0 || nameLen == 0 || nameLen > MAX_SEMAPHORE_NAME_LEN) {
        return -1;
    }

    char name[nameLen];
    if (!Copy_From_User(name, nameUserAddr, nameLen)) {
        return -1;
    }

    id = Init_Semaphore(name, nameLen, resource);
    if (id < 0) {
        return id;
    }
    Register_Semaphore(id);

    return id;
}

/*
 * Acquire a semaphore.
 * Assume that the process has permission to access the semaphore,
 * the call will block until the semaphore count is >= 0.
 * Params:
 *   state->ebx - the semaphore id
 *
 * Returns: 0 if successful, error code (< 0) if unsuccessful
 */
static int Sys_P(struct Interrupt_State* state)
{
    // TODO("P (semaphore acquire) system call");

    return Semaphore_Acquire(state->ebx);
}

/*
 * Release a semaphore.
 * Params:
 *   state->ebx - the semaphore id
 *
 * Returns: 0 if successful, error code (< 0) if unsuccessful
 */
static int Sys_V(struct Interrupt_State* state)
{
    // TODO("V (semaphore release) system call");

    return Semaphore_Release(state->ebx);
}

/*
 * Destroy a semaphore.
 * Params:
 *   state->ebx - the semaphore id
 *
 * Returns: 0 if successful, error code (< 0) if unsuccessful
 */
static int Sys_DestroySemaphore(struct Interrupt_State* state)
{
    // TODO("DestroySemaphore system call");

    int requestId = state->ebx;

    for (int i = 0; i < MAX_SEMAPHORES_REFS; ++i) {
        int id = g_currentThread->semaphores[i];
        if (id == requestId) {
            --g_allSemaphores[id].refCount;
            if (g_allSemaphores[id].refCount == 0) {
                Destroy_Semaphore(id);
            }

            g_currentThread->semaphores[i] = REF_TO_NO_SEMAPHORE;
            --g_currentThread->registeredSemaphores;
        }
    }

    return 0;
}


/*
 * Global table of system call handler functions.
 */
const Syscall g_syscallTable[] = {
    Sys_Null,
    Sys_Exit,
    Sys_PrintString,
    Sys_GetKey,
    Sys_SetAttr,
    Sys_GetCursor,
    Sys_PutCursor,
    Sys_Spawn,
    Sys_Wait,
    Sys_GetPID,
    /* Scheduling and semaphore system calls. */
    Sys_SetSchedulingPolicy,
    Sys_GetTimeOfDay,
    Sys_CreateSemaphore,
    Sys_P,
    Sys_V,
    Sys_DestroySemaphore,
};

/*
 * Number of system calls implemented.
 */
const int g_numSyscalls = sizeof(g_syscallTable) / sizeof(Syscall);
