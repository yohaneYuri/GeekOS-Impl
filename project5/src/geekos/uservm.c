/*
 * Paging-based user mode implementation
 * Copyright (c) 2003,2004 David H. Hovemeyer <daveho@cs.umd.edu>
 * $Revision: 1.50 $
 * 
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "COPYING".
 */

#include <geekos/int.h>
#include <geekos/mem.h>
#include <geekos/paging.h>
#include <geekos/malloc.h>
#include <geekos/string.h>
#include <geekos/argblock.h>
#include <geekos/kthread.h>
#include <geekos/range.h>
#include <geekos/vfs.h>
#include <geekos/user.h>
#include <geekos/gdt.h>
#include <geekos/errno.h>

/* ----------------------------------------------------------------------
 * Private functions
 * ---------------------------------------------------------------------- */

static void Free_Page_Directory(pde_t* pageDir) {
    if (pageDir == 0)
        return;
    // Only pages mapping to virtual address >= 0x80000000 are required to be freed
    for (int i = NUM_PAGE_DIR_ENTRIES / 2; i < NUM_PAGE_DIR_ENTRIES; ++i) {
        pde_t *dirEntry = &pageDir[i];
        if (dirEntry->present) {
            pte_t *table = (pte_t*) (dirEntry->pageTableBaseAddr << PAGE_POWER);
            for (int j = 0; j < NUM_PAGE_TABLE_ENTRIES; ++j) {
                pte_t *tableEntry = &table[j];
                if (tableEntry->present == 1)
                    Free_Page((void*) (tableEntry->pageBaseAddr << PAGE_POWER));
            }
            Free_Page((void*) (dirEntry->pageTableBaseAddr << PAGE_POWER));
        }
    }
    Free_Page(pageDir);
}

static pte_t* Get_Or_Insert_Page_Table(pde_t *dirEntry, uint_t flags) {
    pte_t *table = 0;

    if (dirEntry->present == 1)
        table = (pte_t*) (dirEntry->pageTableBaseAddr << PAGE_POWER);
    else {
        table = Alloc_Page();
        if (table == 0)
            return NULL;
        memset(table, 0, PAGE_SIZE);

        dirEntry->present = 1;
        dirEntry->flags = flags;
        dirEntry->pageTableBaseAddr = (uint_t) table >> PAGE_POWER;
    }

    return table;
}

static int Load_Data_Into_Pageable_Pages(pde_t *pageDir, ulong_t start, void *src, int size) {
    ulong_t end = start + size;
    int numPages = (PAGE_ADDR(end) - PAGE_ADDR(start)) / PAGE_SIZE + 1;

    for (int i = 0; i < numPages; ++i) {
        void *page = 0;
        ulong_t dst, vaddr = Round_Down_To_Page(start) + i * PAGE_SIZE;
        int numBytes;
        pde_t *dirEntry = 0;
        pte_t *table = 0, *tableEntry = 0;

        if (numPages == 1)
            numBytes = size;
        else if (i == 0)
            numBytes = PAGE_SIZE - PAGE_OFFSET(start);
        else if (i == numPages - 1)
            numBytes = PAGE_OFFSET(end);
        else
            numBytes = PAGE_SIZE;

        dirEntry = &pageDir[PAGE_DIRECTORY_INDEX(vaddr)];
        table = Get_Or_Insert_Page_Table(dirEntry, VM_READ | VM_WRITE | VM_EXEC | VM_USER);
        if (table == 0)
            return ENOMEM;
        tableEntry = &table[PAGE_TABLE_INDEX(vaddr)];
        
        page = Alloc_Pageable_Page(tableEntry, vaddr);
        if (page == 0)
            return ENOMEM;
            
        if (i == 0)
            dst = (ulong_t) page + PAGE_OFFSET(start);
        else
            dst = (ulong_t) page;
        
        tableEntry->present = 1;
        tableEntry->flags = VM_READ | VM_WRITE | VM_EXEC | VM_USER;
        tableEntry->pageBaseAddr = (uint_t) page >> PAGE_POWER;

        // Print("Copy: (p) %p -> (p) %p, bytes: %4x, map to (v) %p\n", src, dst, numBytes, vaddr);
        memcpy((void*) dst, src, numBytes);
        
        src = (void*) ((ulong_t) src + numBytes);
    }

    return 0;
}

// TODO: Add private functions
/* ----------------------------------------------------------------------
 * Public functions
 * ---------------------------------------------------------------------- */

/*
 * Destroy a User_Context object, including all memory
 * and other resources allocated within it.
 */
void Destroy_User_Context(struct User_Context* context)
{
    /*
     * Hints:
     * - Free all pages, page tables, and page directory for
     *   the process (interrupts must be disabled while you do this,
     *   otherwise those pages could be stolen by other processes)
     * - Free semaphores, files, and other resources used
     *   by the process
     */
    // TODO("Destroy User_Context data structure after process exits");

    if (context == 0)
        return;
    
    if (context->ldtDescriptor != 0)
        Free_Segment_Descriptor(context->ldtDescriptor);
    if (context->pageDir != 0)
        Free_Page_Directory(context->pageDir);
    Free(context);
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
     * - This will be similar to the same function in userseg.c
     * - Determine space requirements for code, data, argument block,
     *   and stack
     * - Allocate pages for above, map them into user address
     *   space (allocating page directory and page tables as needed)
     * - Fill in initial stack pointer, argument block address,
     *   and code entry point fields in User_Context
     */
    // TODO("Load user program into address space");

    pde_t *oldPageDir = Get_PDBR(), *pageDir = 0, *dirEntry = 0;
    pte_t *table = 0, *tableEntry = 0;
    void *page = 0;
    ulong_t argBlockVaddr, argBlockSize, vaddrTop, initialStackBaseVaddr;
    unsigned numArgs;
    int rc = 0;
    char *argBlockBuf = 0;

    pageDir = Alloc_Page();
    if (pageDir == 0)
        return ENOMEM;
    memset(pageDir, 0, PAGE_SIZE);

    // Copy kernel mappings
    for (int i = 0; i < NUM_PAGE_DIR_ENTRIES / 2; ++i)
        pageDir[i] = oldPageDir[i];
    
    *pUserContext = Malloc(sizeof(struct User_Context));
    if (*pUserContext == 0)
        return ENOMEM;
    (*pUserContext)->pageDir = pageDir;

    // "Useless" segment registers
    (*pUserContext)->ldtDescriptor = Allocate_Segment_Descriptor();
    if ((*pUserContext)->ldtDescriptor == 0) {
        Destroy_User_Context(*pUserContext);
        return ENOMEM;
    }
    Init_LDT_Descriptor((*pUserContext)->ldtDescriptor, (*pUserContext)->ldt, NUM_USER_LDT_ENTRIES);
    (*pUserContext)->ldtSelector = Selector(
        USER_PRIVILEGE, true, Get_Descriptor_Index((*pUserContext)->ldtDescriptor)
    );
    Init_Code_Segment_Descriptor(
        &(*pUserContext)->ldt[0], USER_BASE_VADDR, USER_SEG_LIMIT >> PAGE_POWER, USER_PRIVILEGE
    );
    (*pUserContext)->csSelector = Selector(USER_PRIVILEGE, false, 0);
    Init_Data_Segment_Descriptor(
        &(*pUserContext)->ldt[1], USER_BASE_VADDR, USER_SEG_LIMIT >> PAGE_POWER, USER_PRIVILEGE
    );
    (*pUserContext)->dsSelector = Selector(USER_PRIVILEGE, false, 1);
    
    // All page-aligned

    vaddrTop = 0;
    // Map segments to virtual address, transist data
    for (int i = 0; i < exeFormat->numSegments; ++i) {
        struct Exe_Segment *this = &exeFormat->segmentList[i];
        ulong_t segVaddrStart = USER_BASE_VADDR + this->startAddress;
        ulong_t segVaddrTop = segVaddrStart + this->sizeInMemory;
        
        if (vaddrTop <= segVaddrTop)
            vaddrTop = segVaddrTop;
        
        rc = Load_Data_Into_Pageable_Pages(
            pageDir,
            USER_BASE_VADDR + this->startAddress,
            (void*) (exeFileData + this->offsetInFile),
            this->lengthInFile
        );
        if (rc != 0) {
            Destroy_User_Context(*pUserContext);
            return ENOMEM;
        }
    }

    // And then the argument block
    argBlockVaddr = Round_Up_To_Page(vaddrTop);
    Get_Argument_Block_Size(command, &numArgs, &argBlockSize);
    argBlockBuf = Malloc(argBlockSize);
    if (argBlockBuf == 0) {
        Destroy_User_Context(*pUserContext);
        return ENOMEM;
    }
    Format_Argument_Block(argBlockBuf, numArgs, argBlockVaddr - USER_BASE_VADDR, command);
    rc = Load_Data_Into_Pageable_Pages(pageDir, argBlockVaddr, argBlockBuf, argBlockSize);
    if (rc != 0) {
        Destroy_User_Context(*pUserContext);
        Free(argBlockBuf);
        return ENOMEM;
    }
    Free(argBlockBuf);

    // Stack
    initialStackBaseVaddr = Round_Down_To_Page(VA_END);
    dirEntry = &pageDir[PAGE_DIRECTORY_INDEX(initialStackBaseVaddr)];
    table = Get_Or_Insert_Page_Table(dirEntry, VM_READ | VM_WRITE | VM_EXEC | VM_USER);
    if (table == 0) {
        Destroy_User_Context(*pUserContext);
        return ENOMEM;
    }
    tableEntry = &table[PAGE_TABLE_INDEX(initialStackBaseVaddr)];

    page = Alloc_Pageable_Page(tableEntry, initialStackBaseVaddr);
    if (page == 0) {
        Destroy_User_Context(*pUserContext);
        return ENOMEM;
    }
    tableEntry->present = 1;
    tableEntry->flags = VM_READ | VM_WRITE | VM_EXEC | VM_USER;
    tableEntry->pageBaseAddr = (uint_t) page >> PAGE_POWER;

    // Heap support?

    // Fill other fields
    (*pUserContext)->pageDir = pageDir;
    (*pUserContext)->memory = (char*) USER_BASE_VADDR;
    (*pUserContext)->size = Round_Up_To_Page(vaddrTop - USER_BASE_VADDR) +
        Round_Up_To_Page(argBlockSize) + PAGE_SIZE;
    (*pUserContext)->entryAddr = exeFormat->entryAddr;
    (*pUserContext)->argBlockAddr = argBlockVaddr - USER_BASE_VADDR;
    (*pUserContext)->stackPointerAddr = VA_END - USER_BASE_VADDR;
    (*pUserContext)->refCount = 0;
    memset((*pUserContext)->fdTable, 0, sizeof(struct File*) * USER_MAX_FILES);
    (*pUserContext)->numOpenedFiles = 0;

    return 0;
}

/*
 * Copy data from user buffer into kernel buffer.
 * Returns true if successful, false otherwise.
 */
bool Copy_From_User(void* destInKernel, ulong_t srcInUser, ulong_t numBytes)
{
    /*
     * Hints:
     * - Make sure that user page is part of a valid region
     *   of memory
     * - Remember that you need to add 0x80000000 to user addresses
     *   to convert them to kernel addresses, because of how the
     *   user code and data segments are defined
     * - User pages may need to be paged in from disk before being accessed.
     * - Before you touch (read or write) any data in a user
     *   page, **disable the PAGE_PAGEABLE bit**.
     *
     * Be very careful with race conditions in reading a page from disk.
     * Kernel code must always assume that if the struct Page for
     * a page of memory has the PAGE_PAGEABLE bit set,
     * IT CAN BE STOLEN AT ANY TIME.  The only exception is if
     * interrupts are disabled; because no other process can run,
     * the page is guaranteed not to be stolen.
     */
    // TODO("Copy user data to kernel buffer");

    ulong_t vaddr = USER_BASE_VADDR + srcInUser;

    // Most variables are allocated on stack
    // Be careful of overflowing
    if (vaddr + numBytes <= vaddr)
        return false;
    
    memcpy(destInKernel, (void*) vaddr, numBytes);

    return true;
}

/*
 * Copy data from kernel buffer into user buffer.
 * Returns true if successful, false otherwise.
 */
bool Copy_To_User(ulong_t destInUser, void* srcInKernel, ulong_t numBytes)
{
    /*
     * Hints:
     * - Same as for Copy_From_User()
     * - Also, make sure the memory is mapped into the user
     *   address space with write permission enabled
     */
    // TODO("Copy kernel data to user buffer");

    ulong_t vaddr = USER_BASE_VADDR + destInUser;

    if (vaddr + numBytes <= vaddr)
        return false;

    memcpy((void*) vaddr, srcInKernel, numBytes);
    
    return true;
}

/*
 * Switch to user address space.
 */
void Switch_To_Address_Space(struct User_Context *userContext)
{
    /*
     * - If you are still using an LDT to define your user code and data
     *   segments, switch to the process's LDT
     * - 
     */
    // TODO("Switch_To_Address_Space() using paging");
    extern void* Load_LDTR(ushort_t selector);

    Set_PDBR(userContext->pageDir);
    Load_LDTR(userContext->ldtSelector);
}


