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
    elfHeader elfHeader;
    programHeader *phdrs;
    struct Exe_Segment segments[EXE_MAX_SEGMENTS];
    const int MAGIC_NUMBER_LEN = 4;
    const char MAGIC_NUMBER[4] = {0x7F, 0x45, 0x4C, 0x46};

    if (exeFileLength < sizeof(elfHeader)) {
        return ENOEXEC;
    }

    if (!memcmp(MAGIC_NUMBER, exeFileData, sizeof(char) * MAGIC_NUMBER_LEN)) {
        return ENOEXEC;
    }

    Parse_ELF_Header(exeFileData, &elfHeader);

    if (elfHeader.phnum > EXE_MAX_SEGMENTS) {
        return ENOEXEC;
    }

    phdrs = (programHeader*) Malloc(sizeof(programHeader) * elfHeader.phnum);
    Parse_ELF_Program_Headers(exeFileData, phdrs, elfHeader.phoff, elfHeader.phnum);

    Program_Headers_To_Exe_Segments(phdrs, segments, elfHeader.phnum);
    memcpy(exeFormat, segments, sizeof(struct Exe_Segment) * EXE_MAX_SEGMENTS);
    exeFormat->numSegments = elfHeader.phnum;
    exeFormat->entryAddr = elfHeader.entry;
    
    return 0;
}

void Parse_ELF_Header(char *exeFileData, elfHeader *header) {
    *header = *((elfHeader*) exeFileData);
}

void Parse_ELF_Program_Headers(char *exeFileData, programHeader *table, 
    unsigned int phoff, unsigned short phnum)
{
    for (int i = 0; i < phnum; i++) {
        table[i] = ((programHeader*) (exeFileData + phoff))[i];
    }
}

void Program_Headers_To_Exe_Segments(programHeader* phdrs, struct Exe_Segment *segments,
    unsigned short phnum)
{
    for (int i = 0; i < phnum; i++) {
        segments[i].offsetInFile = phdrs[i].offset;
        segments[i].lengthInFile = phdrs[i].fileSize;
        segments[i].startAddress = phdrs[i].vaddr;
        segments[i].sizeInMemory = phdrs[i].memSize;
        segments[i].protFlags = phdrs[i].flags;
    }
}