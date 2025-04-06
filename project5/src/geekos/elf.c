/*
 * ELF executable loading
 * Copyright (c) 2003, Jeffrey K. Hollingsworth <hollings@cs.umd.edu>
 * Copyright (c) 2003, David H. Hovemeyer <daveho@cs.umd.edu>
 * $Revision: 1.29 $
 * 
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "COPYING".
 */

#include <geekos/errno.h>
#include <geekos/kassert.h>
#include <geekos/ktypes.h>
#include <geekos/screen.h>  /* for debug Print() statements */
#include <geekos/pfat.h>
#include <geekos/malloc.h>
#include <geekos/string.h>
#include <geekos/user.h>
#include <geekos/fileio.h>
#include <geekos/elf.h>

/**
 * From the data of an ELF executable, determine how its segments
 * need to be loaded into memory.
 * @param exeFileData buffer containing the executable file
 * @param exeFileLength length of the executable file in bytes
 * @param exeFormat structure describing the executable's segments
 *   and entry address; to be filled in
 * @return 0 if successful, < 0 on error
 */
int Parse_ELF_Executable(char *exeFileData, ulong_t exeFileLength,
    struct Exe_Format *exeFormat)
{
    elfHeader fileHeader;
    programHeader *programHeaders;
    const int MAGIC_NUMBER_LEN = 4;
    const char MAGIC_NUMBER[4] = {0x7F, 0x45, 0x4C, 0x46};

    if (exeFileData == 0 || exeFormat == 0) {
        return EINVALID;
    }

    if (exeFileLength < sizeof(fileHeader)) {
        return ENOEXEC;
    }
    if (!memcmp(MAGIC_NUMBER, exeFileData, sizeof(char) * MAGIC_NUMBER_LEN)) {
        return ENOEXEC;
    }

    fileHeader = *((elfHeader*) exeFileData);
    if (fileHeader.phnum > EXE_MAX_SEGMENTS) {
        return ENOEXEC;
    }

    programHeaders = (programHeader*) Malloc(sizeof(programHeader) * fileHeader.phnum);
    for (int i = 0; i < fileHeader.phnum; ++i) {
        programHeaders[i] = ((programHeader*) (exeFileData + fileHeader.phoff))[i];

        exeFormat->segmentList[i].offsetInFile = programHeaders[i].offset;
        exeFormat->segmentList[i].lengthInFile = programHeaders[i].fileSize;
        exeFormat->segmentList[i].startAddress = programHeaders[i].vaddr;
        exeFormat->segmentList[i].sizeInMemory = programHeaders[i].memSize;
        exeFormat->segmentList[i].protFlags = programHeaders[i].flags;
    }
    exeFormat->numSegments = fileHeader.phnum;
    exeFormat->entryAddr = fileHeader.entry;
    
    Free(programHeaders);
    return 0;
}
