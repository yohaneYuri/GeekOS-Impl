/*
 * Paging (virtual memory) support
 * Copyright (c) 2003, Jeffrey K. Hollingsworth <hollings@cs.umd.edu>
 * Copyright (c) 2003,2004 David H. Hovemeyer <daveho@cs.umd.edu>
 * $Revision: 1.55 $
 * 
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "COPYING".
 */

#include <geekos/string.h>
#include <geekos/int.h>
#include <geekos/idt.h>
#include <geekos/kthread.h>
#include <geekos/kassert.h>
#include <geekos/screen.h>
#include <geekos/mem.h>
#include <geekos/malloc.h>
#include <geekos/gdt.h>
#include <geekos/segment.h>
#include <geekos/user.h>
#include <geekos/vfs.h>
#include <geekos/crc32.h>
#include <geekos/paging.h>
#include <geekos/bitset.h>

/* ----------------------------------------------------------------------
 * Public data
 * ---------------------------------------------------------------------- */

/* ----------------------------------------------------------------------
 * Private functions/data
 * ---------------------------------------------------------------------- */

static void *s_pagingDevMap;
static struct Page **s_evictedPageList;

#define SECTORS_PER_PAGE (PAGE_SIZE / SECTOR_SIZE)

/*
 * flag to indicate if debugging paging code
 */
int debugFaults = 0;
#define Debug(args...) if (debugFaults) Print(args)


void checkPaging()
{
  unsigned long reg=0;
  __asm__ __volatile__( "movl %%cr0, %0" : "=a" (reg));
  Print("Paging on ? : %d\n", (reg & (1<<31)) != 0);
}


/*
 * Print diagnostic information for a page fault.
 */
static void Print_Fault_Info(uint_t address, faultcode_t faultCode)
{
    extern uint_t g_freePageCount;

    Print("Pid %d, Page Fault received, at address %x (%d pages free)\n",
        g_currentThread->pid, address, g_freePageCount);
    if (faultCode.protectionViolation)
        Print ("   Protection Violation, ");
    else
        Print ("   Non-present page, ");
    if (faultCode.writeFault)
        Print ("Write Fault, ");
    else
        Print ("Read Fault, ");
    if (faultCode.userModeFault)
        Print ("in User Mode\n");
    else
        Print ("in Supervisor Mode\n");
}

/*
 * Handler for page faults.
 * You should call the Install_Interrupt_Handler() function to
 * register this function as the handler for interrupt 14.
 */
/*static*/ void Page_Fault_Handler(struct Interrupt_State* state)
{
    ulong_t address;
    faultcode_t faultCode;
    pde_t *dir = 0, *dirEntry = 0;
    pte_t *table = 0, *tableEntry = 0;

    KASSERT(!Interrupts_Enabled());

    /* Get the address that caused the page fault */
    address = Get_Page_Fault_Address();
    Debug("Page fault @%lx\n", address);

    /* Get the fault code */
    faultCode = *((faultcode_t *) &(state->errorCode));

    /* rest of your handling code here */
    if (address < PAGE_SIZE) {
        Print("Null pointer operation\n");
        Print_Fault_Info(address, faultCode);
        Dump_Interrupt_State(state);
        Exit(-1);
    }

    dir = Get_PDBR();
    KASSERT(dir != 0);
    dirEntry = &dir[PAGE_DIRECTORY_INDEX(address)];

    if (dirEntry->present == 1) {
        table = (pte_t*) (dirEntry->pageTableBaseAddr << PAGE_POWER);
        tableEntry = &table[PAGE_TABLE_INDEX(address)];

        // Acceptable stack overflow
        if (address >= STACK_BOTTOM && address < STACK_BOTTOM + PAGE_SIZE) {
            void *page = Alloc_Pageable_Page(tableEntry , STACK_BOTTOM);
            if (page == 0) {
                Print("Cannot do a stack grow\n");
                Exit(-1);
            }

            tableEntry->present = 1;
            tableEntry->flags = VM_READ | VM_WRITE | VM_EXEC | VM_USER;
            tableEntry->pageBaseAddr = (uint_t) page >> PAGE_POWER;
            return;
        }

        // Swap
        if (tableEntry->present == 0 && tableEntry->kernelInfo == KINFO_PAGE_ON_DISK) {
            struct Page* page = s_evictedPageList[tableEntry->pageBaseAddr];
            if (page == 0 || (page != 0 && page->vaddr != address)) {
                Print("The page in paging file is lost\n");
                Exit(-1);
            }
            page->flags &= ~(PAGE_PAGEABLE);
            page->flags |= PAGE_LOCKED;
            Read_From_Paging_File((void*) Get_Page_Address(page), address, tableEntry->pageBaseAddr);
            page->flags &= ~(PAGE_LOCKED);
            page->flags |= PAGE_PAGEABLE;
            ++page->clock;

            return;
        }
    }
    

    Print ("Unexpected Page Fault received\n");
    Print_Fault_Info(address, faultCode);
    Dump_Interrupt_State(state);
    /* user faults just kill the process */
    if (!faultCode.userModeFault) KASSERT(0);
    /* For now, just kill the thread/process. */
    Exit(-1);
}

/* ----------------------------------------------------------------------
 * Public functions
 * ---------------------------------------------------------------------- */


/*
 * Initialize virtual memory by building page tables
 * for the kernel and physical memory.
 */
void Init_VM(struct Boot_Info *bootInfo)
{
    /*
     * Hints:
     * - Build kernel page directory and page tables
     * - Call Enable_Paging() with the kernel page directory
     * - Install an interrupt handler for interrupt 14,
     *   page fault
     * - Do not map a page at address 0; this will help trap
     *   null pointer references
     */
    // TODO("Build initial kernel page directory and page tables");

    int numPages = bootInfo->memSizeKB >> 2;
    pde_t *kPageDir = 0;

    kPageDir = Alloc_Page();
    KASSERT(kPageDir != 0);
    memset(kPageDir, 0, PAGE_SIZE);

    for (int i = 1; i < numPages; ++i) {
        ulong_t paddr = i * PAGE_SIZE;
        pde_t *dirEntry = 0;
        pte_t *table = 0, *tableEntry = 0;

        dirEntry = &kPageDir[PAGE_DIRECTORY_INDEX(paddr)];
        if (dirEntry->present == 1)
            table = (pte_t*) (dirEntry->pageTableBaseAddr << PAGE_POWER);
        else {
            table = Alloc_Page();
            KASSERT(table != 0);
            memset(table, 0, PAGE_SIZE);

            dirEntry->present = 1;
            dirEntry->flags = VM_READ | VM_WRITE | VM_EXEC;
            dirEntry->pageTableBaseAddr = (uint_t) table >> PAGE_POWER;
        }
        tableEntry = &table[PAGE_TABLE_INDEX(paddr)];

        tableEntry->present = 1;
        tableEntry->flags = VM_READ | VM_WRITE | VM_EXEC;
        tableEntry->pageBaseAddr = paddr >> PAGE_POWER;
    }

    Enable_Paging(kPageDir);
    Install_Interrupt_Handler(14, Page_Fault_Handler);
}

/**
 * Initialize paging file data structures.
 * All filesystems should be mounted before this function
 * is called, to ensure that the paging file is available.
 */
void Init_Paging(void)
{
    // TODO("Initialize paging file data structures");

    struct Paging_Device *pagingDev = 0;
    int numPages, numListBytes;

    pagingDev = Get_Paging_Device();
    KASSERT(pagingDev != 0);
    numPages = pagingDev->numSectors / SECTORS_PER_PAGE;
    numListBytes = numPages * sizeof(struct Page*);

    s_pagingDevMap = Create_Bit_Set(numPages);
    KASSERT(s_pagingDevMap != 0);
    s_evictedPageList = Malloc(numListBytes);
    KASSERT(s_evictedPageList != 0);
    memset(s_evictedPageList, 0, numListBytes);
}

/**
 * Find a free bit of disk on the paging file for this page.
 * Interrupts must be disabled.
 * @return index of free page sized chunk of disk space in
 *   the paging file, or -1 if the paging file is full
 */
int Find_Space_On_Paging_File(void)
{
    KASSERT(!Interrupts_Enabled());
    // TODO("Find free page in paging file");

    struct Paging_Device *pagingDev = Get_Paging_Device();
    int numPages = pagingDev->numSectors / SECTORS_PER_PAGE;

    for (int i = 0; i < numPages; ++i) {
        if (!Is_Bit_Set(s_pagingDevMap, i))
            return i;
    }

    return -1;
}

/**
 * Free a page-sized chunk of disk space in the paging file.
 * Interrupts must be disabled.
 * @param pagefileIndex index of the chunk of disk space
 */
void Free_Space_On_Paging_File(int pagefileIndex)
{
    KASSERT(!Interrupts_Enabled());
    // TODO("Free page in paging file");

    KASSERT(Is_Bit_Set(s_pagingDevMap, pagefileIndex));
    Clear_Bit(s_pagingDevMap, pagefileIndex);
}

/**
 * Write the contents of given page to the indicated block
 * of space in the paging file.
 * @param paddr a pointer to the physical memory of the page
 * @param vaddr virtual address where page is mapped in user memory
 * @param pagefileIndex the index of the page sized chunk of space
 *   in the paging file
 */
void Write_To_Paging_File(void *paddr, ulong_t vaddr, int pagefileIndex)
{
    struct Page *page = Get_Page((ulong_t) paddr);
    KASSERT(!(page->flags & PAGE_PAGEABLE)); /* Page must be locked! */
    // TODO("Write page data to paging file");

    struct Paging_Device *pagingDev = Get_Paging_Device();
    KASSERT(!Is_Bit_Set(s_pagingDevMap, pagefileIndex));
    int rc = Block_Write(
        pagingDev->dev,
        pagingDev->startSector + pagefileIndex * SECTORS_PER_PAGE,
        paddr
    );
    if (rc != 0) {
        Print("Cannot swap the required page to disk\n");
        Exit(-1);
    }

    Set_Bit(s_pagingDevMap, pagefileIndex);
    s_evictedPageList[pagefileIndex] = page;
}

/**
 * Read the contents of the indicated block
 * of space in the paging file into the given page.
 * @param paddr a pointer to the physical memory of the page
 * @param vaddr virtual address where page will be re-mapped in
 *   user memory
 * @param pagefileIndex the index of the page sized chunk of space
 *   in the paging file
 */
void Read_From_Paging_File(void *paddr, ulong_t vaddr, int pagefileIndex)
{
    struct Page *page = Get_Page((ulong_t) paddr);
    KASSERT(!(page->flags & PAGE_PAGEABLE)); /* Page must be locked! */
    // TODO("Read page data from paging file");

    struct Paging_Device *pagingDev = Get_Paging_Device();
    KASSERT(Is_Bit_Set(s_pagingDevMap, pagefileIndex));
    int rc = Block_Read(
        pagingDev->dev,
        pagingDev->startSector + pagefileIndex * SECTORS_PER_PAGE,
        paddr
    );
    if (rc != 0) {
        Print("Cannot swap the required page back\n");
        Exit(-1);
    }

    Clear_Bit(s_pagingDevMap, pagefileIndex);
}

// struct Page* Get_Evicted_Page(int pagefileIndex) {
//     KASSERT(Is_Bit_Set(s_pagingDevMap, pagefileIndex));
//     return s_evictedPageList[pagefileIndex];
// }
