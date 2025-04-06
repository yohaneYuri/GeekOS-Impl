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

// Dispatcher for code reusage
static int Do_Open_File(struct Interrupt_State* state, bool isDir) {
    int rc = 0;
    ulong_t pathUserAddr = state->ebx,
        pathLen = state->ecx;
    char *path = 0;
    struct File *file = 0;
    struct User_Context *context = g_currentThread->userContext;

    if (context->numOpenedFiles >= USER_MAX_FILES) return EMFILE;
    
    if (pathLen == 0) return EINVALID;

    path = Malloc(pathLen + 1);
    if (path == 0) return ENOMEM;
    if (!Copy_From_User(path, pathUserAddr, pathLen)) {
        rc = -1;
        Free(path);
    }
    path[pathLen] = 0;

    Enable_Interrupts();
    if (isDir)
        rc = Open_Directory(path, &file);
    else {
        ulong_t mode = state->edx;
        rc = Open(path, mode, &file);
    }
    Disable_Interrupts();
    Free(path);
    if (rc != 0) return rc;

    for (int i = 0; i < USER_MAX_FILES; ++i) {
        if (context->fdTable[i] == 0) {
            context->fdTable[i] = file;
            ++context->numOpenedFiles;
            break;
        }
    }

    return 0;
}

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
        return -1;
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
 * Mount a filesystem.
 * Params:
 * state->ebx - contains a pointer to the Mount_Syscall_Args structure
 *   which contains the block device name, mount prefix,
 *   and filesystem type
 *
 * Returns:
 *   0 if successful, error code if unsuccessful
 */
static int Sys_Mount(struct Interrupt_State *state)
{
    int rc = 0;
    struct VFS_Mount_Request *args = 0;

    /* Allocate space for VFS_Mount_Request struct. */
    if ((args = (struct VFS_Mount_Request *) Malloc(sizeof(struct VFS_Mount_Request))) == 0) {
        rc = ENOMEM;
        goto done;
    }

    /* Copy the mount arguments structure from user space. */
    if (!Copy_From_User(args, state->ebx, sizeof(struct VFS_Mount_Request))) {
        rc = EINVALID;
        goto done;
    }

    /*
     * Hint: use devname, prefix, and fstype from the args structure
     * and invoke the Mount() VFS function.  You will need to check
     * to make sure they are correctly nul-terminated.
     */

    if (args->devname[BLOCKDEV_MAX_NAME_LEN] != 0 ||
        args->prefix[VFS_MAX_PATH_LEN] != 0 ||
        args->fstype[VFS_MAX_FS_NAME_LEN] != 0) {
        rc = EINVALID;
        goto done;
    }

    Enable_Interrupts();
    rc = Mount(args->devname, args->prefix, args->fstype);
    Disable_Interrupts();

done:
    if (args != 0) Free(args);
    return rc;
}

/*
 * Open a file.
 * Params:
 *   state->ebx - address of user string containing path of file to open
 *   state->ecx - length of path
 *   state->edx - file mode flags
 *
 * Returns: a file descriptor (>= 0) if successful,
 *   or an error code (< 0) if unsuccessful
 */
static int Sys_Open(struct Interrupt_State *state)
{
    return Do_Open_File(state, false);
}

/*
 * Open a directory.
 * Params:
 *   state->ebx - address of user string containing path of directory to open
 *   state->ecx - length of path
 *
 * Returns: a file descriptor (>= 0) if successful,
 *   or an error code (< 0) if unsuccessful
 */
static int Sys_OpenDirectory(struct Interrupt_State *state)
{
    return Do_Open_File(state, true);
}

/*
 * Close an open file or directory.
 * Params:
 *   state->ebx - file descriptor of the open file or directory
 * Returns: 0 if successful, or an error code (< 0) if unsuccessful
 */
static int Sys_Close(struct Interrupt_State *state)
{
    int rc = 0;
    ulong_t fd = state->ebx;
    struct User_Context *context = g_currentThread->userContext;
    struct File *file = 0;

    if (fd > USER_MAX_FILES) return ENOTFOUND;

    file = context->fdTable[fd];
    if (file == 0) return -1;

    Enable_Interrupts();
    rc = Close(file);
    Disable_Interrupts();

    if (rc == 0) {
        context->fdTable[fd] = 0;
        --context->numOpenedFiles;
    }

    return rc;
}

/*
 * Delete a file.
 * Params:
 *   state->ebx - address of user string containing path to delete
 *   state->ecx - length of path
 *
 * Returns: 0 if successful, error code (< 0) if unsuccessful
 */
static int Sys_Delete(struct Interrupt_State *state)
{
    int rc = 0;
    ulong_t pathUserAddr = state->ebx,
        pathLen = state->ecx;
    char *path = 0;

    if (pathLen == 0) return EINVALID;

    path = Malloc(pathLen + 1);
    if (path == 0) return ENOMEM;
    if (!Copy_From_User(path, pathUserAddr, pathLen)) {
        Free(path);
        return -1;
    }
    path[pathLen] = 0;

    Enable_Interrupts();
    rc = Delete(path);
    Disable_Interrupts();

    Free(path);
    return rc;
}

/*
 * Read from an open file.
 * Params:
 *   state->ebx - file descriptor to read from
 *   state->ecx - user address of buffer to read into
 *   state->edx - number of bytes to read
 *
 * Returns: number of bytes read, 0 if end of file,
 *   or error code (< 0) on error
 */
static int Sys_Read(struct Interrupt_State *state)
{
    int rc = 0;
    ulong_t fd = state->ebx,
        bufUserAddr = state->ecx,
        numBytes = state->edx;
    void *buf = 0;
    struct File *file = 0;

    if (fd > USER_MAX_FILES) return ENOTFOUND;

    file = g_currentThread->userContext->fdTable[fd];
    if (file == 0) return -1;

    buf = Malloc(numBytes);
    if (buf == 0) return ENOMEM;

    Enable_Interrupts();
    rc = Read(file, buf, numBytes);
    Disable_Interrupts();
    if (rc < 0) {
        Free(buf);
        return rc;
    }

    if (!Copy_To_User(bufUserAddr, buf, numBytes)) {
        Free(buf);
        return -1;
    }

    Free(buf);
    return rc;
}

/*
 * Read a directory entry from an open directory handle.
 * Params:
 *   state->ebx - file descriptor of the directory
 *   state->ecx - user address of struct VFS_Dir_Entry to copy entry into
 * Returns: 0 if successful, error code (< 0) if unsuccessful
 */
static int Sys_ReadEntry(struct Interrupt_State *state)
{
    int rc = 0;
    ulong_t fd = state->ebx, vfsEntryUserAddr = state->ecx;
    struct VFS_Dir_Entry vfsEntry;
    struct File *file = 0;

    if (fd > USER_MAX_FILES) return ENOTFOUND;

    file = g_currentThread->userContext->fdTable[fd];
    if (file == 0) return -1;

    Enable_Interrupts();
    rc = Read_Entry(file, &vfsEntry);
    Disable_Interrupts();
    if (rc == ENOTFOUND) return 1; // Gives a stop signal
    if (rc != 0) return rc;

    if (!Copy_To_User(vfsEntryUserAddr, &vfsEntry, sizeof(struct VFS_Dir_Entry)))
        rc = -1;
    return rc;
}

/*
 * Write to an open file.
 * Params:
 *   state->ebx - file descriptor to write to
 *   state->ecx - user address of buffer get data to write from
 *   state->edx - number of bytes to write
 *
 * Returns: number of bytes written,
 *   or error code (< 0) on error
 */
static int Sys_Write(struct Interrupt_State *state)
{
    int rc = 0;
    ulong_t fd = state->ebx,
        bufUserAddr = state->ecx,
        numBytes = state->edx;
    void *buf = 0;
    struct File *file = 0;

    if (fd > USER_MAX_FILES) return ENOTFOUND;

    file = g_currentThread->userContext->fdTable[fd];
    if (file == 0) return -1;

    buf = Malloc(numBytes);
    if (buf == 0) return ENOMEM;

    if (!Copy_From_User(buf, bufUserAddr, numBytes)) {
        Free(buf);
        return -1;
    }

    Enable_Interrupts();
    rc = Write(file, buf, numBytes);
    Disable_Interrupts();

    Free(buf);
    return rc;
}

/*
 * Get file metadata.
 * Params:
 *   state->ebx - address of user string containing path of file
 *   state->ecx - length of path
 *   state->edx - user address of struct VFS_File_Stat object to store metadata in
 *
 * Returns: 0 if successful, error code (< 0) if unsuccessful
 */
static int Sys_Stat(struct Interrupt_State *state)
{
    int rc = 0;
    ulong_t pathUserAddr = state->ebx,
        pathLen = state->ecx,
        vfsStatUserAddr = state->edx;
    struct VFS_File_Stat vfsStat;
    char *path = 0;

    if (pathLen == 0) return EINVALID;
    path = Malloc(pathLen + 1);
    if (path == 0) return ENOMEM;
    if (!Copy_From_User(path, pathUserAddr, pathLen)) {
        Free(path);
        return -1;
    }
    path[pathLen] = 0;

    Enable_Interrupts();
    rc = Stat(path, &vfsStat);
    Disable_Interrupts();
    Free(path);
    if (rc != 0) return rc;

    if (!Copy_To_User(vfsStatUserAddr, &vfsStat, sizeof(struct VFS_File_Stat)))
        rc = -1;
    return rc;
}

/*
 * Get metadata of an open file.
 * Params:
 *   state->ebx - file descriptor to get metadata for
 *   state->ecx - user address of struct VFS_File_Stat object to store metadata in
 *
 * Returns: 0 if successful, error code (< 0) if unsuccessful
 */
static int Sys_FStat(struct Interrupt_State *state)
{
    int rc = 0;
    ulong_t fd = state->ebx, vfsStatUserAddr = state->ecx;
    struct VFS_File_Stat vfsStat;

    if (fd > USER_MAX_FILES) return ENOTFOUND;

    Enable_Interrupts();
    rc = FStat(g_currentThread->userContext->fdTable[fd], &vfsStat);
    Disable_Interrupts();
    if (rc != 0) return rc;

    if (!Copy_To_User(vfsStatUserAddr, &vfsStat, sizeof(struct VFS_File_Stat)))
        rc = -1;
    return rc;
}

/*
 * Change the access position in a file
 * Params:
 *   state->ebx - file descriptor 
 *   state->ecx - position in file
 *
 * Returns: 0 if successful, error code (< 0) if unsuccessful
 */
static int Sys_Seek(struct Interrupt_State *state)
{
    int rc = 0;
    ulong_t fd = state->ebx, pos = state->ecx;
    struct File *file = 0;

    if (fd > USER_MAX_FILES) return ENOTFOUND;

    file = g_currentThread->userContext->fdTable[fd];
    if (file == 0) return -1;

    Enable_Interrupts();
    rc = Seek(file, pos);
    Disable_Interrupts();

    return rc;
}

/*
 * Create directory
 * Params:
 *   state->ebx - address of user string containing path of new directory
 *   state->ecx - length of path
 *
 * Returns: 0 if successful, error code (< 0) if unsuccessful
 */
static int Sys_CreateDir(struct Interrupt_State *state)
{
    int rc = 0;
    ulong_t pathUserAddr = state->ebx,
        pathLen = state->ecx;
    char *path = 0;

    if (pathLen == 0) return EINVALID;

    path = Malloc(pathLen + 1);
    if (path == 0) return ENOMEM;
    if (!Copy_From_User(path, pathUserAddr, pathLen)) {
        rc = -1;
        goto fail;
    }
    path[pathLen] = 0;

    Enable_Interrupts();
    rc = Create_Directory(path);
    Disable_Interrupts();

fail:
    Free(path);
    return rc;
}

/*
 * Flush filesystem buffers
 * Params: none 
 * Returns: 0 if successful, error code (< 0) if unsuccessful
 */
static int Sys_Sync(struct Interrupt_State *state)
{
    int rc = 0;

    Enable_Interrupts();
    rc = Sync();
    Disable_Interrupts();

    return rc;
}
/*
 * Format a device
 * Params:
 *   state->ebx - address of user string containing device to format
 *   state->ecx - length of device name string
 *   state->edx - address of user string containing filesystem type 
 *   state->esi - length of filesystem type string

 * Returns: 0 if successful, error code (< 0) if unsuccessful
 */
static int Sys_Format(struct Interrupt_State *state)
{
    int rc = 0;
    ulong_t devNameUserAddr = state->ebx,
        devNameLen = state->ecx,
        fsTyUserAddr = state->edx,
        fsTyLen = state->esi;
    char *devName = 0, *fsTy = 0;

    if (devNameLen == 0 || fsTyLen == 0) return EINVALID;

    devName = Malloc(devNameLen + 1);
    fsTy = Malloc(fsTyLen + 1);
    if (devName == 0 || fsTy == 0) {
        rc = ENOMEM;
        goto fail;
    }

    if (!Copy_From_User(devName, devNameUserAddr, devNameLen) ||
        !Copy_From_User(fsTy, fsTyUserAddr, fsTyLen)) {
        rc = -1;
        goto fail;
    }
    devName[devNameLen] = 0;
    fsTy[fsTyLen] = 0;

    Enable_Interrupts();
    rc = Format(devName, fsTy);
    Disable_Interrupts();

fail:
cleanup:
    if (devName != 0) Free(devName);
    if (fsTy != 0) Free(fsTy);

    return rc;
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
    /* File I/O system calls. */
    Sys_Mount,
    Sys_Open,
    Sys_OpenDirectory,
    Sys_Close,
    Sys_Delete,
    Sys_Read,
    Sys_ReadEntry,
    Sys_Write,
    Sys_Stat,
    Sys_FStat,
    Sys_Seek,
    Sys_CreateDir,
    Sys_Sync,
    Sys_Format,
};

/*
 * Number of system calls implemented.
 */
const int g_numSyscalls = sizeof(g_syscallTable) / sizeof(Syscall);
