/*
 * Segmentation-based user mode implementation
 * Copyright (c) 2001,2003 David H. Hovemeyer <daveho@cs.umd.edu>
 * $Revision: 1.23 $
 * 
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "COPYING".
 */

#include <geekos/ktypes.h>
#include <geekos/kassert.h>
#include <geekos/defs.h>
#include <geekos/mem.h>
#include <geekos/string.h>
#include <geekos/malloc.h>
#include <geekos/int.h>
#include <geekos/gdt.h>
#include <geekos/segment.h>
#include <geekos/tss.h>
#include <geekos/kthread.h>
#include <geekos/argblock.h>
#include <geekos/user.h>
#include <geekos/errno.h>

/* ----------------------------------------------------------------------
 * Variables
 * ---------------------------------------------------------------------- */

#define DEFAULT_USER_STACK_SIZE 8192


/* ----------------------------------------------------------------------
 * Private functions
 * ---------------------------------------------------------------------- */


/*
 * Create a new user context of given size
 */
static struct User_Context* Create_User_Context(ulong_t size)
{
    struct User_Context *context = (struct User_Context*) Malloc(sizeof(struct User_Context));
    if (!context) {
        return NULL;
    }

    context->memory = (char*) Malloc(size);
    if (!context->memory) {
        Destroy_User_Context(context);
        return NULL;
    }
    context->size = size;
    context->refCount = 0;

    return context;
}



static bool Validate_User_Memory(struct User_Context* userContext,
    ulong_t userAddr, ulong_t bufSize)
{
    ulong_t avail;

    if (userAddr >= userContext->size)
        return false;

    avail = userContext->size - userAddr;
    if (bufSize > avail)
        return false;

    return true;
}

/* ----------------------------------------------------------------------
 * Public functions
 * ---------------------------------------------------------------------- */

/*
 * Destroy a User_Context object, including all memory
 * and other resources allocated within it.
 */
void Destroy_User_Context(struct User_Context* userContext)
{
    /*
     * Hints:
     * - you need to free the memory allocated for the user process
     * - don't forget to free the segment descriptor allocated
     *   for the process's LDT
     */
    // TODO("Destroy a User_Context");

    if (!userContext) {
        return;
    }

    if (userContext->ldtDescriptor) {
        Free_Segment_Descriptor(userContext->ldtDescriptor);
    }
    if (userContext->memory) {
        Free(userContext->memory);
    }
    Free(userContext);
}

/*
 * Load a user executable into memory by creating a User_Context
 * data structure.
 * Params:
 * exeFileData - a buffer containing the executable to load
 * exeFileLength - number of bytes in exeFileData
 * exeFormat - parsed ELF segment information describing how to
 *   load the executable's text and data segments, and the
 *   code entry point address
 * command - string containing the complete command to be executed:
 *   this should be used to create the argument block for the
 *   process
 * pUserContext - reference to the pointer where the User_Context
 *   should be stored
 *
 * Returns:
 *   0 if successful, or an error code (< 0) if unsuccessful
 */
int Load_User_Program(char *exeFileData, ulong_t exeFileLength,
    struct Exe_Format *exeFormat, const char *command,
    struct User_Context **pUserContext)
{
    /*
     * Hints:
     * - Determine where in memory each executable segment will be placed
     * - Determine size of argument block and where it memory it will
     *   be placed
     * - Copy each executable segment into memory
     * - Format argument block in memory
     * - In the created User_Context object, set code entry point
     *   address, argument block address, and initial kernel stack pointer
     *   address
     */
    // TODO("Load a user executable into a user memory space using segmentation");

    // Who was driven crazy by addressing of x86?
    // Oh, that was me!

    ulong_t addressTop = 0;

    ulong_t argBlockSize, argBlockAddr;
    unsigned numArgs;

    if (exeFileData == 0 || exeFormat == 0) {
        return EINVALID;
    }

    for (int i = 0; i < exeFormat->numSegments; ++i) {
        struct Exe_Segment *segment = &exeFormat->segmentList[i];
        ulong_t segmentAddressTop = segment->startAddress + segment->sizeInMemory;

        if (segmentAddressTop > addressTop) {
            addressTop = segmentAddressTop;
        }
    }
    if (addressTop == 0) {
        return ENOEXEC;
    }
    Get_Argument_Block_Size(command, &numArgs, &argBlockSize);
    argBlockAddr = addressTop;
    addressTop += argBlockSize;
    addressTop = Round_Up_To_Page(addressTop) + DEFAULT_USER_STACK_SIZE;
    *pUserContext = Create_User_Context(addressTop);
    if (!*pUserContext) {
        return ENOMEM;
    }

    for (int i = 0; i < exeFormat->numSegments; ++i) {
        struct Exe_Segment *segment = &exeFormat->segmentList[i];
        memcpy(
            (*pUserContext)->memory + segment->startAddress,
            exeFileData + segment->offsetInFile,
            segment->lengthInFile
        );
    }
    Format_Argument_Block(
        (*pUserContext)->memory + argBlockAddr,
        numArgs, argBlockAddr, command
    );

    (*pUserContext)->ldtDescriptor = Allocate_Segment_Descriptor();
    if (!(*pUserContext)->ldtDescriptor) {
        return EUNSPECIFIED;
    }
    Init_LDT_Descriptor((*pUserContext)->ldtDescriptor, (*pUserContext)->ldt, NUM_USER_LDT_ENTRIES);
    (*pUserContext)->ldtSelector = Selector(
        USER_PRIVILEGE, true, Get_Descriptor_Index((*pUserContext)->ldtDescriptor)
    );

    // Protected flat mode
    Init_Code_Segment_Descriptor(
        &(*pUserContext)->ldt[0], (ulong_t) (*pUserContext)->memory, addressTop >> PAGE_POWER, USER_PRIVILEGE
    );
    (*pUserContext)->csSelector = Selector(USER_PRIVILEGE, false, 0);
    Init_Data_Segment_Descriptor(
        &(*pUserContext)->ldt[1], (ulong_t) (*pUserContext)->memory, addressTop >> PAGE_POWER, USER_PRIVILEGE
    );
    (*pUserContext)->dsSelector = Selector(USER_PRIVILEGE, false, 1);

    (*pUserContext)->entryAddr = exeFormat->entryAddr;
    (*pUserContext)->argBlockAddr = argBlockAddr;
    (*pUserContext)->stackPointerAddr = addressTop;

    return 0;
    // What's' `exeFileLength` for?
}

/*
 * Copy data from user memory into a kernel buffer.
 * Params:
 * destInKernel - address of kernel buffer
 * srcInUser - address of user buffer
 * bufSize - number of bytes to copy
 *
 * Returns:
 *   true if successful, false if user buffer is invalid (i.e.,
 *   doesn't correspond to memory the process has a right to
 *   access)
 */
bool Copy_From_User(void* destInKernel, ulong_t srcInUser, ulong_t bufSize)
{
    /*
     * Hints:
     * - the User_Context of the current process can be found
     *   from g_currentThread->userContext
     * - the user address is an index relative to the chunk
     *   of memory you allocated for it
     * - make sure the user buffer lies entirely in memory belonging
     *   to the process
     */
    // TODO("Copy memory from user buffer to kernel buffer");
    
    struct User_Context *context = g_currentThread->userContext;

    if (destInKernel == 0) {
        return false;
    }
    if (!Validate_User_Memory(context, srcInUser, bufSize)) {
        return false;
    }

    memcpy(destInKernel, context->memory + srcInUser, bufSize);

    return true;
}

/*
 * Copy data from kernel memory into a user buffer.
 * Params:
 * destInUser - address of user buffer
 * srcInKernel - address of kernel buffer
 * bufSize - number of bytes to copy
 *
 * Returns:
 *   true if successful, false if user buffer is invalid (i.e.,
 *   doesn't correspond to memory the process has a right to
 *   access)
 */
bool Copy_To_User(ulong_t destInUser, void* srcInKernel, ulong_t bufSize)
{
    /*
     * Hints: same as for Copy_From_User()
     */
    // TODO("Copy memory from kernel buffer to user buffer");

    struct User_Context *context = g_currentThread->userContext;

    if (srcInKernel == 0) {
        return false;
    }
    if (!Validate_User_Memory(context, destInUser, bufSize)) {
        return false;
    }

    memcpy(context->memory + destInUser, srcInKernel, bufSize);

    return true;
}

/*
 * Switch to user address space belonging to given
 * User_Context object.
 * Params:
 * userContext - the User_Context
 */
void Switch_To_Address_Space(struct User_Context *userContext)
{
    /*
     * Hint: you will need to use the lldt assembly language instruction
     * to load the process's LDT by specifying its LDT selector.
     */
    // TODO("Switch to user address space using segmentation/LDT");

    extern void Load_LDTR(ushort_t selector);

    KASSERT(userContext != 0);
    
    Load_LDTR(userContext->ldtSelector);
}

