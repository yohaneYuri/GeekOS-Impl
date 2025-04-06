/*
 * GeekOS file system
 * Copyright (c) 2004, David H. Hovemeyer <daveho@cs.umd.edu>
 * $Revision: 1.54 $
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "COPYING".
 */


// This project took me 43 days to complete, from February 22, 2024 to April 6, 2024,
// more than 200 hours, an average of 8 hours a day, which almost exhausted all my energy, no holidays.
// I wanted to say a lot, but when it was finished, I didn't know what to say, full of emotion.
// Now I think the quality of my code is really worrying. Fixing bugs is like playing whack-a-mole.
// I really realized the importance of good planning in software engineering.
// The kernel is really amazing. Pray for computer science!
// - yohaneYuri

#include <limits.h>
#include <geekos/errno.h>
#include <geekos/kassert.h>
#include <geekos/screen.h>
#include <geekos/malloc.h>
#include <geekos/string.h>
#include <geekos/bitset.h>
#include <geekos/synch.h>
#include <geekos/bufcache.h>
#include <geekos/gosfs.h>

// Found a small amount code among a large number of bugs
// That's software engineering
// IT IS ABSOLUTELY A SHIT MOUNTAIN

struct Super_Block {
    int magic;
    ulong_t numBlocks;
    ulong_t blockMapStart;
    ulong_t inodeTableStart;
    ulong_t dataBlocksStart;
};

#define GOSFS_MAGIC 0x7dd0cafe
#define GOSFS_SUPERBLOCK_OFFSET 0
#define GOSFS_BLOCK_MAP_OFFSET 1
#define GOSFS_NUM_INODE_BLOCKS 4

#define GOSFS_ABSENT_PTR 0 // Reserved: unused
#define GOSFS_ROOTDIR_INODE_PTR 1
#define GOSFS_NUM_BITS_PER_FS_BLOCK (GOSFS_FS_BLOCK_SIZE * 8)

#define GET_INDEX_AND_OFFSET(ty, ptr, size) \
ty ptr##Index, ptr##Offset;                 \
do {                                        \
    ptr##Index = ptr / size;                \
    ptr##Offset = ptr % size;               \
} while (0)                                 \

#define GOSFS_NUM_PTRS_IN_DIRECT (GOSFS_NUM_DIRECT_BLOCKS * GOSFS_NUM_PTRS_PER_BLOCK)
#define GOSFS_NUM_PTRS_IN_INDIRECT \
    (GOSFS_NUM_INDIRECT_BLOCKS * GOSFS_NUM_PTRS_PER_BLOCK * GOSFS_NUM_PTRS_PER_BLOCK)
#define GOSFS_NUM_PTRS_IN_2x_INDIRECT \
    (GOSFS_NUM_PTRS_IN_INDIRECT * \
    GOSFS_NUM_PTRS_PER_BLOCK * GOSFS_NUM_PTRS_PER_BLOCK * GOSFS_NUM_PTRS_PER_BLOCK)
#define GOSFS_DIRECT_INDEX_TOP GOSFS_NUM_PTRS_IN_DIRECT
#define GOSFS_INDIRECT_INDEX_TOP (GOSFS_DIRECT_INDEX_TOP + GOSFS_NUM_PTRS_IN_INDIRECT)
#define GOSFS_2X_INDIRECT_INDEX_TOP (GOSFS_INDIRECT_INDEX_TOP + GOSFS_NUM_PTRS_IN_2x_INDIRECT)

#define GOSFS_MAX_SIZE_DIRECT_SUPPORTS (GOSFS_NUM_DIRECT_BLOCKS * GOSFS_FS_BLOCK_SIZE)
#define GOSFS_MAX_SIZE_INDIRECT_SUPPORTS (GOSFS_MAX_SIZE_DIRECT_SUPPORTS + \
    GOSFS_NUM_INDIRECT_BLOCKS * GOSFS_NUM_PTRS_PER_BLOCK * GOSFS_FS_BLOCK_SIZE)
// Overflows when calculating 2x-indirect, use long long variable instead

// We should use RwLock, but Mutex instead here for simplicity
// In memory file instance
struct GOSFS_File {
    char path[VFS_MAX_PATH_LEN + 1];
    ulong_t size;
    ulong_t flags;
    ulong_t inodePtr;
    ulong_t blockList[GOSFS_NUM_BLOCK_PTRS];
    struct VFS_ACL_Entry acl[VFS_MAX_ACL_ENTRIES];
    struct Mutex lock;
    DEFINE_LINK(GOSFS_File_List, GOSFS_File);
};
DEFINE_LIST(GOSFS_File_List, GOSFS_File);
IMPLEMENT_LIST(GOSFS_File_List, GOSFS_File);

struct GOSFS {
    ulong_t numBlocks;
    ulong_t blockBitmapStart;
    ulong_t inodeTableStart;
    ulong_t dataBlocksStart;
    struct FS_Buffer_Cache *cache;
    struct GOSFS_File_List filesOpened;
    struct Mutex lock;
};

// TODO: add exclusive access & concurrency support

/* ----------------------------------------------------------------------
 * Private data and functions
 * ---------------------------------------------------------------------- */
 
// Avoid undefined functions
static int Alloc_Block(struct GOSFS *self, ulong_t *pBlockPtr);
static int Dealloc_Block(struct GOSFS *self, ulong_t targetBlockPtr);
static int Alloc_Inode(struct GOSFS *self, ulong_t *pInodePtr, const char *name, bool isDir);
static int Dealloc_Inode(struct GOSFS *self, ulong_t targetInodePtr);
static int Find_Entry(ulong_t selfPtr, const char *name, ulong_t *pTargetInodePtr, struct GOSFS *fs);
static int Insert_Entry(ulong_t selfPtr, ulong_t targetPtr, struct GOSFS *fs);

#define NOT_FOUND -1

// Common

// Set all bytes to 0 and mark the block modified
static __inline__ void Clear_Block(struct FS_Buffer *blockBuf, struct FS_Buffer_Cache *cache) {
    memset(blockBuf->data, 0, GOSFS_FS_BLOCK_SIZE);
    Modify_FS_Buffer(cache, blockBuf);
}

static int Find_Inode_Ptr(
    ulong_t blockPtr, const char *name, ulong_t *pInodePtr, struct GOSFS *fs
) {
    int rc = 0;
    struct FS_Buffer *buf = 0;

    if (blockPtr == GOSFS_ABSENT_PTR) return NOT_FOUND;

    rc = Get_FS_Buffer(fs->cache, blockPtr, &buf);
    if (rc != 0) return rc;

    for (int i = 0; i < GOSFS_NUM_PTRS_PER_BLOCK; ++i) {
        ulong_t this = *((ulong_t*) buf->data + i);
        GET_INDEX_AND_OFFSET(ulong_t, this, GOSFS_DIR_ENTRIES_PER_BLOCK);
        struct FS_Buffer *inodeBlockBuf = 0;
        struct GOSFS_Dir_Entry *pInode = 0;

        rc = Get_FS_Buffer(fs->cache, fs->inodeTableStart + thisIndex, &inodeBlockBuf);
        if (rc != 0) goto fail;

        pInode = (struct GOSFS_Dir_Entry*) inodeBlockBuf->data + thisOffset;
        if (strcmp(name, pInode->filename) == 0) {
            *pInodePtr = this;
            Release_FS_Buffer(fs->cache, inodeBlockBuf);
            goto cleanup;
        }

        Release_FS_Buffer(fs->cache, inodeBlockBuf);
    }

    rc = NOT_FOUND;

fail:
cleanup:
    Release_FS_Buffer(fs->cache, buf);
    return rc;
}

static int Find_Inode_Ptr_Rec(
    ulong_t startBlockPtr, uint_t level, const char *name, ulong_t *pInodePtr, struct GOSFS *fs
) {
    int rc = 0;
    struct FS_Buffer *buf = 0;

    if (startBlockPtr == GOSFS_ABSENT_PTR) return NOT_FOUND;

    // Leaf function
    if (level == 0) return Find_Inode_Ptr(startBlockPtr, name, pInodePtr, fs);

    rc = Get_FS_Buffer(fs->cache, startBlockPtr, &buf);
    if (rc != 0) return rc;

    for (int j = 0; j < GOSFS_NUM_PTRS_PER_BLOCK; ++j) {
        ulong_t blockPtr = *((ulong_t*) buf->data + j);

        rc = Find_Inode_Ptr_Rec(blockPtr, level - 1, name, pInodePtr, fs);
        if (rc != NOT_FOUND) goto fail;
    }

    rc = NOT_FOUND;

fail:
    Release_FS_Buffer(fs->cache, buf);
    return rc;
}

static __inline__ void Next_Path_Seg(char **pStartPoint, char *name) {
    char *segStart = 0, *segEnd = 0;
    int segLen;

    if (**pStartPoint == 0) {
        // So that strlen(name) == 0 indicates no segments left
        name[0] = 0;
        return;
    }
    
    KASSERT(**pStartPoint == '/');
    segStart = *pStartPoint + 1;

    segEnd = strchr(segStart, '/');
    if (segEnd != 0)
        --segEnd;
    else {
        // It's the last segment
        segEnd = segStart;
        while (*(segEnd + 1) != 0) ++segEnd;
    }
    segLen = segEnd - segStart + 1;

    memcpy(name, segStart, segLen);
    name[segLen] = 0;

    // Put it on the next '/', maybe '\0'
    *pStartPoint = segEnd + 1;
}

static __inline__ char* Get_File_Name(const char *path) {
    char *ret = 0, *head = 0, *tail = 0;
    int len;

    head = strrchr(path, '/');
    if (*(head + 1) != 0) ++head;
    tail = path;
    while (*(tail + 1) != 0) ++tail;
    len = tail - head + 1;

    ret = Malloc(len + 1);
    if (ret == 0) return 0;
    memcpy(ret, head, len);
    ret[len] = 0;

    return ret;
}

static int Insert_Ptr(ulong_t blockPtr, ulong_t targetPtr, struct GOSFS *fs) {
    int rc = 0;
    struct FS_Buffer *buf = 0;

    rc = Get_FS_Buffer(fs->cache, blockPtr, &buf);
    if (rc != 0) return rc;

    for (int i = 0; i < GOSFS_NUM_PTRS_PER_BLOCK; ++i) {
        ulong_t *pThisPtr = (ulong_t*) buf->data + i;

        if (*pThisPtr == GOSFS_ABSENT_PTR) {
            // Print("Insert %d to %d, offset: %d\n", targetPtr, blockPtr, i);
            *pThisPtr = targetPtr;
            Modify_FS_Buffer(fs->cache, buf);

            Release_FS_Buffer(fs->cache, buf);
            return 0;
        }
    }

    Release_FS_Buffer(fs->cache, buf);
    return NOT_FOUND;
}

static int Insert_Ptr_Rec(ulong_t startBlockPtr, ulong_t targetPtr, uint_t level, struct GOSFS *fs) {
    int rc = 0;
    struct FS_Buffer *buf = 0;

    // Leaf
    if (level == 0) return Insert_Ptr(startBlockPtr, targetPtr, fs);

    rc = Get_FS_Buffer(fs->cache, startBlockPtr, &buf);
    if (rc != 0) return rc;

    for (int i = 0; i < GOSFS_NUM_PTRS_PER_BLOCK; ++i) {
        ulong_t *pThisPtr = (ulong_t*) buf->data + i;

        if (*pThisPtr == GOSFS_ABSENT_PTR) {
            rc = Alloc_Block(fs, pThisPtr);
            if (rc != 0) goto fail;
        }

        rc = Insert_Ptr_Rec(*pThisPtr, targetPtr, level - 1, fs);
        if (rc == NOT_FOUND) continue;
        if (rc != 0) {
            int temp = rc;
            rc = Dealloc_Block(fs, *pThisPtr);
            if (rc != 0) goto fail;
            *pThisPtr = GOSFS_ABSENT_PTR;
            rc = temp;
            goto fail;
        }

        Release_FS_Buffer(fs->cache, buf);
        return 0;
    }

    rc = NOT_FOUND;

fail:
    Release_FS_Buffer(fs->cache, buf);
    return rc;
}

static __inline__ char* Get_Father_Dir_Path(const char *path) {
    char *ret = 0, *tail = 0;
    int len;

    // Root directory has no father directory
    if (strcmp("/", path) == 0) return 0;

    tail = strrchr(path, '/');
    // Children of root directory
    if (tail == path) {
        ret = Malloc(1 + 1);
        if (ret == 0) return 0;

        strcpy(ret, "/");
        return ret;
    }
    --tail;
    len = tail - path + 1;

    ret = Malloc(len + 1);
    if (ret == 0) return 0;
    memcpy(ret, path, len);
    ret[len] = 0;
    
    return ret;
}

static __inline__ void Copy_ACL(struct VFS_ACL_Entry *dst, struct VFS_ACL_Entry *src) {
    memcpy(dst, src, VFS_MAX_ACL_ENTRIES * sizeof(struct VFS_ACL_Entry));
}

static __inline__ void Copy_Inode_Info(struct GOSFS_File *dst, struct GOSFS_Dir_Entry *src) {
    dst->size = src->size;
    dst->flags = src->flags;
    memcpy(dst->blockList, src->blockList, GOSFS_NUM_BLOCK_PTRS * sizeof(ulong_t));
    memcpy(dst->acl, src->acl, VFS_MAX_ACL_ENTRIES * sizeof(struct VFS_ACL_Entry));
}

static __inline__ void Copy_Stat(struct VFS_File_Stat *dst, struct GOSFS_Dir_Entry *src) {
    dst->size = src->size;
    dst->isDirectory = (src->flags & GOSFS_DIRENTRY_ISDIRECTORY) != 0;
    dst->isSetuid = (src->flags & GOSFS_DIRENTRY_SETUID) != 0;
    Copy_ACL(dst->acls, src->acl);
}

static __inline__ void Copy_Stat_Entry(struct VFS_Dir_Entry *dst, struct GOSFS_Dir_Entry *src) {
    strcpy(dst->name, src->filename);
    Copy_Stat(&dst->stats, src);
}

static __inline__ int Try_Find_Next_Available_Entry(struct File *dir, ulong_t *pPtr) {
    // When encounters an absent entry, increace both `filePos` and
    // `endPos`, the actual size is saved in `fsData`
    while (*pPtr == GOSFS_ABSENT_PTR) {
        ++dir->filePos;
        ++dir->endPos;
        ++pPtr;
        // It's out of the bound of current block, just retry
        if (dir->filePos % GOSFS_NUM_PTRS_PER_BLOCK == 0) return NOT_FOUND;
    }

    return 0;
}

static int Get_Next_Entry(struct File *dir, struct VFS_Dir_Entry *entry) {
    int rc = 0;
    struct GOSFS_File *fileInstance = dir->fsData;
    struct GOSFS *fs = dir->mountPoint->fsData;
    struct FS_Buffer *buf = 0;
    struct GOSFS_Dir_Entry *nextInode = 0;
    ulong_t ptr, *pPtr = 0;

    // Reject if no entries left
    if (dir->filePos >= dir->endPos) return ENOTFOUND;

    // File.filePos is the index of the inode we will read

    if (dir->filePos < GOSFS_DIRECT_INDEX_TOP) {
        ulong_t temp = dir->filePos;
        ulong_t i = temp / GOSFS_NUM_PTRS_PER_BLOCK;
        ulong_t offset = temp % GOSFS_NUM_PTRS_PER_BLOCK;

        rc = Get_FS_Buffer(fs->cache, fileInstance->blockList[i], &buf);
        if (rc != 0) return rc;
        pPtr = (ulong_t*) buf->data + offset;
        rc = Try_Find_Next_Available_Entry(dir, pPtr);
        if (rc != 0) {
            Release_FS_Buffer(fs->cache, buf);
            return rc;
        }
        ptr = *pPtr;
        Release_FS_Buffer(fs->cache, buf);

        goto found;
    }

    if (dir->filePos < GOSFS_INDIRECT_INDEX_TOP) {
        ulong_t temp = dir->filePos;
        ulong_t i, j, offset;

        temp -= GOSFS_DIRECT_INDEX_TOP;
        i = temp / (GOSFS_NUM_PTRS_PER_BLOCK * GOSFS_NUM_PTRS_PER_BLOCK);
        temp -= i * (GOSFS_NUM_PTRS_PER_BLOCK * GOSFS_NUM_PTRS_PER_BLOCK);
        j = temp / GOSFS_NUM_PTRS_PER_BLOCK;
        offset = temp % GOSFS_NUM_PTRS_PER_BLOCK;

        rc = Get_FS_Buffer(fs->cache, fileInstance->blockList[GOSFS_NUM_DIRECT_BLOCKS + i], &buf);
        if (rc != 0) return rc;
        ptr = *((ulong_t*) buf->data + j);
        KASSERT(ptr != GOSFS_ABSENT_PTR);
        Release_FS_Buffer(fs->cache, buf);

        rc = Get_FS_Buffer(fs->cache, ptr, &buf);
        if (rc != 0) return rc;
        pPtr = (ulong_t*) buf->data + offset;
        rc = Try_Find_Next_Available_Entry(dir, pPtr);
        if (rc != 0) {
            Release_FS_Buffer(fs->cache, buf);
            return rc;
        }
        ptr = *pPtr;
        Release_FS_Buffer(fs->cache, buf);

        goto found;
    }

    if (dir->filePos < GOSFS_INDIRECT_INDEX_TOP) {
        ulong_t temp = dir->filePos;
        ulong_t i, j, k, offset;

        temp -= GOSFS_INDIRECT_INDEX_TOP;
        i = temp / (GOSFS_NUM_PTRS_PER_BLOCK * GOSFS_NUM_PTRS_PER_BLOCK * GOSFS_NUM_PTRS_PER_BLOCK);
        temp -= i * (GOSFS_NUM_PTRS_PER_BLOCK * GOSFS_NUM_PTRS_PER_BLOCK * GOSFS_NUM_PTRS_PER_BLOCK);
        j = temp / (GOSFS_NUM_PTRS_PER_BLOCK * GOSFS_NUM_PTRS_PER_BLOCK);
        temp -= j * (GOSFS_NUM_PTRS_PER_BLOCK * GOSFS_NUM_PTRS_PER_BLOCK);
        k = temp / GOSFS_NUM_PTRS_PER_BLOCK;
        offset = temp % GOSFS_NUM_PTRS_PER_BLOCK;

        rc = Get_FS_Buffer(
            fs->cache,
            fileInstance->blockList[GOSFS_NUM_DIRECT_BLOCKS + GOSFS_NUM_INDIRECT_BLOCKS + i],
            &buf
        );
        if (rc != 0) return rc;
        ptr = *((ulong_t*) buf->data + j);
        KASSERT(ptr != GOSFS_ABSENT_PTR);
        Release_FS_Buffer(fs->cache, buf);

        rc = Get_FS_Buffer(fs->cache, ptr, &buf);
        if (rc != 0) return rc;
        ptr = *((ulong_t*) buf->data + k);
        KASSERT(ptr != GOSFS_ABSENT_PTR);
        Release_FS_Buffer(fs->cache, buf);

        rc = Get_FS_Buffer(fs->cache, ptr, &buf);
        if (rc != 0) return rc;
        pPtr = (ulong_t*) buf->data + offset;
        rc = Try_Find_Next_Available_Entry(dir, pPtr);
        if (rc != 0) {
            Release_FS_Buffer(fs->cache, buf);
            return rc;
        }
        ptr = *pPtr;
        Release_FS_Buffer(fs->cache, buf);

        goto found;
    }

    return ENOTFOUND;

found:
    GET_INDEX_AND_OFFSET(ulong_t, ptr, GOSFS_DIR_ENTRIES_PER_BLOCK);
    rc = Get_FS_Buffer(fs->cache, fs->inodeTableStart + ptrIndex, &buf);
    if (rc != 0) return rc;
    nextInode = (struct GOSFS_Dir_Entry*) buf->data + ptrOffset;
    Copy_Stat_Entry(entry, nextInode);
    Release_FS_Buffer(fs->cache, buf);

    ++dir->filePos;
    return 0;
}

static __inline__ bool Block_Has_No_Ptrs(struct FS_Buffer *blockBuf) {
    for (int i = 0; i < GOSFS_NUM_PTRS_PER_BLOCK; ++i) {
        ulong_t *pPtr = (ulong_t*) blockBuf->data + i;
        if (*pPtr != GOSFS_ABSENT_PTR) return false;
    }
    return true;
}

static int Delete_Ptr(ulong_t *pBlockPtr, ulong_t targetPtr, struct GOSFS *fs) {
    int rc = 0;
    struct FS_Buffer *buf = 0;

    rc = Get_FS_Buffer(fs->cache, *pBlockPtr, &buf);
    if (rc != 0) return rc;

    for (int i = 0; i < GOSFS_NUM_PTRS_PER_BLOCK; ++i) {
        ulong_t *pThisPtr = (ulong_t*) buf->data + i;

        if (*pThisPtr == targetPtr) {
            *pThisPtr = GOSFS_ABSENT_PTR;
            Modify_FS_Buffer(fs->cache, buf);

            // Do a check here to determine whether the block will be freed
            if (Block_Has_No_Ptrs(buf)) {
                rc = Dealloc_Block(fs, *pBlockPtr);
                if (rc != 0) {
                    Release_FS_Buffer(fs->cache, buf);
                    return rc;
                }
                *pBlockPtr = GOSFS_ABSENT_PTR;
            }

            Release_FS_Buffer(fs->cache, buf);
            return 0;
        }
    }

    Release_FS_Buffer(fs->cache, buf);
    return NOT_FOUND;
}

static int Delete_Ptr_Rec(
    ulong_t *pStartBlockPtr, ulong_t targetPtr, uint_t level, struct GOSFS *fs
) {
    int rc = 0;
    struct FS_Buffer *buf = 0;

    // Although finding, inserting, deleting recursively have a
    // large amount of shared logic and code, I seperate them to
    // independent functions due to their different behaviors

    // Leaf function
    if (level == 0) return Delete_Ptr(pStartBlockPtr, targetPtr, fs);


    rc = Get_FS_Buffer(fs->cache, *pStartBlockPtr, &buf);
    if (rc != 0) return rc;

    for (int i = 0; i < GOSFS_NUM_PTRS_PER_BLOCK; ++i) {
        ulong_t *pThisPtr = (ulong_t*) buf->data + i;

        if (*pThisPtr == GOSFS_ABSENT_PTR) continue;

        rc = Delete_Ptr_Rec(pThisPtr, targetPtr, level - 1, fs);
        if (rc == NOT_FOUND) continue;
        if (rc != 0) goto fail;
        if (*pThisPtr == GOSFS_ABSENT_PTR) Modify_FS_Buffer(fs->cache, buf);

        if (Block_Has_No_Ptrs(buf)) {
            rc = Dealloc_Block(fs, *pStartBlockPtr);
            if (rc != 0) {
                Release_FS_Buffer(fs->cache, buf);
                return rc;
            }
            *pStartBlockPtr = GOSFS_ABSENT_PTR;
        }

        Release_FS_Buffer(fs->cache, buf);
        return 0;
    }

    rc = NOT_FOUND;

fail:
    Release_FS_Buffer(fs->cache, buf);
    return rc;
}

static int Free_Inode_Blocks(struct GOSFS_Dir_Entry *inode, struct GOSFS *fs) {
    int rc = 0;

    // I think it's not necessary to make the progress into functions
    // We don't have extra information to trace blocks allocated, so traverse stupidly!

    // Direct
    for (int i = 0; i < GOSFS_NUM_DIRECT_BLOCKS; ++i) {
        ulong_t ptr = inode->blockList[i];

        if (ptr == GOSFS_ABSENT_PTR) continue;

        rc = Dealloc_Block(fs, ptr);
        if (rc != 0) return rc;
    }

    // Indirect
    for (int i = 0; i < GOSFS_NUM_INDIRECT_BLOCKS; ++i) {
        struct FS_Buffer *indirectBuf = 0;
        ulong_t ptr = inode->blockList[GOSFS_NUM_DIRECT_BLOCKS + i];

        if (ptr == GOSFS_ABSENT_PTR) continue;

        rc = Get_FS_Buffer(fs->cache, ptr, &indirectBuf);
        if (rc != 0) return rc;

        for (int j = 0; j < GOSFS_NUM_PTRS_PER_BLOCK; ++j) {
            // No variable shadowing... No...
            ulong_t indirectPtr = *((ulong_t*) indirectBuf->data + j);

            if (indirectPtr == GOSFS_ABSENT_PTR) continue;

            rc = Dealloc_Block(fs, indirectPtr);
            if (rc != 0) {
                Release_FS_Buffer(fs->cache, indirectBuf);
                return rc;
            }
        }

        rc = Dealloc_Block(fs, ptr);
        Release_FS_Buffer(fs->cache, indirectBuf);
        if (rc != 0) return rc;
    }

    // 2x-indirect
    for (int i = 0; i < GOSFS_NUM_2X_INDIRECT_BLOCKS; ++i) {
        struct FS_Buffer *indirectBuf = 0;
        ulong_t ptr =
            inode->blockList[GOSFS_NUM_DIRECT_BLOCKS + GOSFS_NUM_INDIRECT_BLOCKS + i];
        
        if (ptr == GOSFS_ABSENT_PTR) continue;

        rc = Get_FS_Buffer(fs->cache, ptr, &indirectBuf);
        if (rc != 0) return rc;

        for (int j = 0; j < GOSFS_NUM_PTRS_PER_BLOCK; ++j) {
            ulong_t indirectPtr = *((ulong_t*) indirectBuf->data + j);
            struct FS_Buffer *indirect2xBuf = 0;

            if (indirectPtr == GOSFS_ABSENT_PTR) continue;

            rc = Get_FS_Buffer(fs->cache, indirectPtr, &indirect2xBuf);
            if (rc != 0) {
                Release_FS_Buffer(fs->cache, indirectBuf);
                return rc;
            }

            for (int k = 0; k < GOSFS_NUM_PTRS_PER_BLOCK; ++k) {
                ulong_t indirect2xPtr = *((ulong_t*) indirect2xBuf->data + k);

                if (indirect2xPtr == GOSFS_ABSENT_PTR) continue;

                rc = Dealloc_Block(fs, indirect2xPtr);
                if (rc != 0) {
                    Release_FS_Buffer(fs->cache, indirect2xBuf);
                    Release_FS_Buffer(fs->cache, indirectBuf);
                    return rc;
                }
            }

            Release_FS_Buffer(fs->cache, indirect2xBuf);
        }

        Release_FS_Buffer(fs->cache, indirectBuf);
    }

    return 0;
}

// This function will create new blocks when the area is not present
static int Get_Or_Insert_Block_Of_Current_Byte(
    ulong_t *blockListInMem, ulong_t pos, ulong_t *pBlockPtr, struct GOSFS *fs
) {
    int rc = 0;
    struct FS_Buffer *buf = 0;
    ulong_t *pPtr = 0, ptr;

    if (pos < GOSFS_MAX_SIZE_DIRECT_SUPPORTS) {
        pPtr = &blockListInMem[pos / GOSFS_FS_BLOCK_SIZE];
        if (*pPtr == GOSFS_ABSENT_PTR) {
            rc = Alloc_Block(fs, pPtr);
            if (rc != 0) return rc;
        }

        ptr = *pPtr;
        *pBlockPtr = ptr;
        return 0;
    }

    if (pos < GOSFS_MAX_SIZE_INDIRECT_SUPPORTS) {
        ulong_t temp = pos;
        ulong_t i, j;
        
        temp -= GOSFS_MAX_SIZE_DIRECT_SUPPORTS;
        i = temp / (GOSFS_NUM_PTRS_PER_BLOCK * GOSFS_FS_BLOCK_SIZE);
        temp -= i * (GOSFS_NUM_PTRS_PER_BLOCK * GOSFS_FS_BLOCK_SIZE);
        j = temp / GOSFS_FS_BLOCK_SIZE;

        pPtr = &blockListInMem[GOSFS_NUM_DIRECT_BLOCKS + i];
        if (*pPtr == GOSFS_ABSENT_PTR) {
            rc = Alloc_Block(fs, pPtr);
            if (rc != 0) return rc;
        }
        ptr = *pPtr;

        rc = Get_FS_Buffer(fs->cache, ptr, &buf);
        if (rc != 0) return rc;
        pPtr = (ulong_t*) buf->data + j;
        if (*pPtr == GOSFS_ABSENT_PTR) {
            rc = Alloc_Block(fs, pPtr);
            if (rc != 0) {
                Release_FS_Buffer(fs->cache, buf);
                return rc;
            }
            Modify_FS_Buffer(fs->cache, buf);
        }
        ptr = *pPtr;
        *pBlockPtr = ptr;
        Release_FS_Buffer(fs->cache, buf);

        return 0;
    }

    // Overflows
    unsigned long long temp = pos;
    unsigned long long i, j, k;
    unsigned long long bytesPer2xIndirectBlock;

    bytesPer2xIndirectBlock = GOSFS_NUM_PTRS_PER_BLOCK;
    bytesPer2xIndirectBlock *= GOSFS_NUM_PTRS_PER_BLOCK;
    bytesPer2xIndirectBlock *= GOSFS_FS_BLOCK_SIZE;

    temp -= GOSFS_MAX_SIZE_INDIRECT_SUPPORTS;
    i = temp / bytesPer2xIndirectBlock;
    temp -= i * bytesPer2xIndirectBlock;
    j = temp / (GOSFS_NUM_PTRS_PER_BLOCK * GOSFS_FS_BLOCK_SIZE);
    temp -= j * (GOSFS_NUM_PTRS_PER_BLOCK * GOSFS_FS_BLOCK_SIZE);
    k = temp / GOSFS_FS_BLOCK_SIZE;

    pPtr = &blockListInMem[GOSFS_NUM_DIRECT_BLOCKS + GOSFS_NUM_INDIRECT_BLOCKS + i];
    if (*pPtr == GOSFS_ABSENT_PTR) {
        rc = Alloc_Block(fs, pPtr);
        if (rc != 0) return rc;
    }
    ptr = *pPtr;

    rc = Get_FS_Buffer(fs->cache, ptr, &buf);
    if (rc != 0) return rc;
    pPtr = (ulong_t*) buf->data + j;
    if (*pPtr == GOSFS_ABSENT_PTR) {
        rc = Alloc_Block(fs, pPtr);
        if (rc != 0) {
            Release_FS_Buffer(fs->cache, buf);
            return rc;
        }
        Modify_FS_Buffer(fs->cache, buf);
    }
    ptr = *pPtr;
    Release_FS_Buffer(fs->cache, buf);

    rc = Get_FS_Buffer(fs->cache, ptr, &buf);
    if (rc != 0) return rc;
    pPtr = (ulong_t*) buf->data + k;
    if (*pPtr == GOSFS_ABSENT_PTR) {
        rc = Alloc_Block(fs, pPtr);
        if (rc != 0) {
            Release_FS_Buffer(fs->cache, buf);
            return rc;
        }
        Modify_FS_Buffer(fs->cache, buf);
    }
    ptr = *pPtr;
    *pBlockPtr = ptr;
    Release_FS_Buffer(fs->cache, buf);

    return 0;

    return NOT_FOUND;
}

// File system operations

static __inline__ int Get_RootDir(struct GOSFS *self, struct GOSFS_Dir_Entry *pRootDir) {
    int rc = 0;
    struct FS_Buffer *buf = 0;

    rc = Get_FS_Buffer(self->cache, self->inodeTableStart, &buf);
    if (rc != 0) return rc;

    *pRootDir = *((struct GOSFS_Dir_Entry*) buf->data + GOSFS_ROOTDIR_INODE_PTR);

    Release_FS_Buffer(self->cache, buf);
    return 0;
}

// Stores the pointer in `*pBlockPtr` if success
static int Alloc_Block(struct GOSFS *self, ulong_t *pBlockPtr) {
    int rc = 0;
    ulong_t numBlockMapBlocks = self->inodeTableStart - self->blockBitmapStart;

    // Traverse all block bitmap blocks
    for (int i = 0; i < numBlockMapBlocks; ++i) {
        struct FS_Buffer *buf = 0;

        rc = Get_FS_Buffer(self->cache, self->blockBitmapStart + i, &buf);
        if (rc != 0) return rc;

        // For each bit in the bitmap block
        for (int j = 0; j < GOSFS_NUM_BITS_PER_FS_BLOCK; ++j) {
            // Print("Block %d, offset %d, stat: %d\n", i, j, Is_Bit_Set(buf->data, j));
            if (!Is_Bit_Set(buf->data, j)) {
                struct FS_Buffer *newBlockBuf = 0;
                ulong_t ptr = i * GOSFS_NUM_BITS_PER_FS_BLOCK + j;

                // We provide user with a clean block, best service!
                rc = Get_FS_Buffer(self->cache, ptr, &newBlockBuf);
                if (rc != 0) {
                    Release_FS_Buffer(self->cache, buf);
                    return rc;
                }
                Clear_Block(newBlockBuf, self->cache);
                Release_FS_Buffer(self->cache, newBlockBuf);

                Set_Bit(buf->data, j);
                Modify_FS_Buffer(self->cache, buf);

                *pBlockPtr = ptr;

                Release_FS_Buffer(self->cache, buf);
                return 0;
            }
        }

        Release_FS_Buffer(self->cache, buf);
    }

    return ENOSPACE;
}

// TODO: handle the return value smarter
static int Dealloc_Block(struct GOSFS *self, ulong_t targetBlockPtr) {
    int rc = 0;
    GET_INDEX_AND_OFFSET(ulong_t, targetBlockPtr, GOSFS_NUM_BITS_PER_FS_BLOCK);
    struct FS_Buffer *buf = 0;

    rc = Get_FS_Buffer(self->cache, self->blockBitmapStart + targetBlockPtrIndex, &buf);
    if (rc != 0) return rc;

    KASSERT(Is_Bit_Set(buf->data, targetBlockPtrOffset));
    Clear_Bit(buf->data, targetBlockPtrOffset);
    Modify_FS_Buffer(self->cache, buf);

    Release_FS_Buffer(self->cache, buf);
    return 0;
}

// Stores the pointer in `*pInodePtr` if success
static int Alloc_Inode(struct GOSFS *self, ulong_t *pInodePtr, const char *name, bool isDir) {
    int rc = 0;
    ulong_t numInodeTableBlocks = self->dataBlocksStart - self->inodeTableStart;
    
    for (int i = 0; i < numInodeTableBlocks; ++i) {
        struct FS_Buffer *buf = 0;

        rc = Get_FS_Buffer(self->cache, self->inodeTableStart + i, &buf);
        if (rc != 0) return rc;

        for (int j = 0; j < GOSFS_DIR_ENTRIES_PER_BLOCK; ++j) {
            struct GOSFS_Dir_Entry *pInode = (struct GOSFS_Dir_Entry*) buf->data + j;

            // Skip the reserved inode
            if (i == 0 && j == 0) continue;

            if (!(pInode->flags & GOSFS_DIRENTRY_USED)) {
                pInode->flags |= GOSFS_DIRENTRY_USED;
                if (isDir) pInode->flags |= GOSFS_DIRENTRY_ISDIRECTORY;
                strcpy(pInode->filename, name);
                pInode->size = 0;
                memset(pInode->blockList, 0, GOSFS_NUM_BLOCK_PTRS * sizeof(ulong_t));
                Modify_FS_Buffer(self->cache, buf);

                *pInodePtr = i * GOSFS_DIR_ENTRIES_PER_BLOCK + j;

                Release_FS_Buffer(self->cache, buf);
                return 0;
            }
        }

        Release_FS_Buffer(self->cache, buf);
    }

    return ENOSPACE;
}

static int Dealloc_Inode(struct GOSFS *self, ulong_t targetInodePtr) {
    int rc = 0;
    GET_INDEX_AND_OFFSET(ulong_t, targetInodePtr, GOSFS_DIR_ENTRIES_PER_BLOCK);
    struct FS_Buffer *buf = 0;
    struct GOSFS_Dir_Entry *pInode = 0;

    rc = Get_FS_Buffer(self->cache, self->inodeTableStart + targetInodePtrIndex, &buf);
    if (rc != 0) return rc;

    pInode = (struct GOSFS_Dir_Entry*) buf->data + targetInodePtrOffset;
    KASSERT(pInode->flags & GOSFS_DIRENTRY_USED);
    // If it's a non-empty directory, reject
    if (pInode->flags & GOSFS_DIRENTRY_ISDIRECTORY && pInode->size != 0) {
        Release_FS_Buffer(self->cache, buf);
        return -1;
    }

    pInode->flags = 0;
    Modify_FS_Buffer(self->cache, buf);

    // Clean up the resource held by the inode
    // Ensure its success
    while (Free_Inode_Blocks(pInode, self) != 0);

    Release_FS_Buffer(self->cache, buf);
    return 0;
}

static __inline__ int Get_Num_Block_Bitmap_Blocks(struct GOSFS *self) {
    return self->inodeTableStart - self->blockBitmapStart;
}

static __inline__ int Get_Num_Inode_Table_Blocks(struct GOSFS *self) {
    return self->dataBlocksStart - self->inodeTableStart;
}

// `pInode` is optional
static int Lookup_File(struct GOSFS *self, const char *path, ulong_t *pInodePtr, struct GOSFS_Dir_Entry *pInode) {
    int rc = 0;
    char *name = 0, *startPoint = 0;
    ulong_t traversalInodePtr, dirInodePtr;
    struct FS_Buffer *buf = 0;

    // If path is root directory
    if (strcmp("/", path) == 0) {
        struct GOSFS_Dir_Entry rootDirInode;
        rc = Get_RootDir(self, &rootDirInode);
        if (rc != 0) return rc;
        *pInodePtr = GOSFS_ROOTDIR_INODE_PTR;
        if (pInode != 0) *pInode = rootDirInode;
        return 0;
    }

    // Name buffer for path directories
    name = Malloc(GOSFS_FILENAME_MAX + 1);
    if (name == 0) return ENOMEM;

    traversalInodePtr = GOSFS_ROOTDIR_INODE_PTR;
    startPoint = path;
    Next_Path_Seg(&startPoint, name);
    while (strlen(name) != 0) {
        rc = Find_Entry(traversalInodePtr, name, &traversalInodePtr, self);
        if (rc != 0) goto fail;

        dirInodePtr = traversalInodePtr;
        Next_Path_Seg(&startPoint, name);
    }

    // Got you!
    GET_INDEX_AND_OFFSET(ulong_t, traversalInodePtr, GOSFS_DIR_ENTRIES_PER_BLOCK);
    rc = Get_FS_Buffer(self->cache, self->inodeTableStart + traversalInodePtrIndex, &buf);
    if (rc != 0) goto fail;
    if (pInode != 0) *pInode = *((struct GOSFS_Dir_Entry*) buf->data + traversalInodePtrOffset);
    *pInodePtr = traversalInodePtr;
    Release_FS_Buffer(self->cache, buf);
    

    goto cleanup;

fail:
    if (rc == NOT_FOUND) rc = ENOTFOUND;
cleanup:
    Free(name);
    return rc;
}

static __inline__ struct GOSFS_File* Lookup_Opened(struct GOSFS *self, const char *path) {
    struct GOSFS_File *file = Get_Front_Of_GOSFS_File_List(&self->filesOpened);

    while (file != 0) {
        if (strcmp(file->path, path) == 0) return file;
        file = Get_Next_In_GOSFS_File_List(file);
    }
    return 0;
}

static int Update_Inode_Cache(struct GOSFS *self, const char *path, ulong_t inodePtr) {
    int rc = 0;
    struct GOSFS_Dir_Entry *inode = 0;
    struct GOSFS_File *file = Get_Front_Of_GOSFS_File_List(&self->filesOpened);
    GET_INDEX_AND_OFFSET(ulong_t, inodePtr, GOSFS_DIR_ENTRIES_PER_BLOCK);
    struct FS_Buffer *buf = 0;

    rc = Get_FS_Buffer(self->cache, self->inodeTableStart + inodePtrIndex, &buf);
    if (rc != 0) return rc;
    inode = (struct GOSFS_Dir_Entry*) buf->data + inodePtrOffset;

    while (file != 0) {
        if (strcmp(file->path, path) == 0) {
            Copy_Inode_Info(file, inode);
            Release_FS_Buffer(self->cache, buf);
            return 0;
        }

        file = Get_Next_In_GOSFS_File_List(file);
    }

    Release_FS_Buffer(self->cache, buf);
    return 0;
}

static int Create_File(struct GOSFS *self, const char *path, bool isDir, ulong_t *pInodePtr) {
    int rc = 0;
    char *name = 0, *dirPath = 0;
    ulong_t dirInodePtr;

    // Find its directory
    dirPath = Get_Father_Dir_Path(path);
    if (dirPath == 0) goto memfail;
    rc = Lookup_File(self, dirPath, &dirInodePtr, 0);
    if (rc != 0) goto createfail;

    name = Get_File_Name(path);
    if (name == 0) goto memfail;

    rc = Alloc_Inode(self, pInodePtr, name, isDir);
    if (rc != 0) goto createfail;

    // Insert the new file's inode to its directory's inode
    rc = Insert_Entry(dirInodePtr, *pInodePtr, self);
    if (rc != 0) goto createfail;
    // Don't forget cached inode
    Update_Inode_Cache(self, dirPath, dirInodePtr);

    goto cleanup;

memfail:
    rc = ENOMEM;
createfail:
cleanup:
    if (name != 0) Free(name);
    if (dirPath != 0) Free(dirPath);
    return rc;
}

static int Open_File(
    struct Mount_Point *mountPoint, const char *path, struct File_Ops *ops, int mode, struct File **pFile
) {
    int rc = 0;
    struct GOSFS *fs = mountPoint->fsData;
    struct GOSFS_Dir_Entry targetInode;
    ulong_t targetInodePtr;
    struct GOSFS_File *file = 0;

    // Lookup files already opened
    file = Lookup_Opened(fs, path);
    if (file != 0) {
        *pFile = Allocate_File(ops, 0, file->size, file, mode, mountPoint);
        if (*pFile == 0) goto memfail;
        return 0;
    }

    // No? Lookup on the disk
    rc = Lookup_File(fs, path, &targetInodePtr, &targetInode);
    if (rc != 0 && rc != ENOTFOUND) return rc;

    if (rc == ENOTFOUND && !(mode & O_CREATE)) return rc;

    // Create file with O_EXCL
    if (mode & O_CREATE && mode & O_EXCL && rc == 0) return EEXIST;

    // Create file
    if (mode & O_CREATE && rc == ENOTFOUND) {
        rc = Create_File(fs, path, false, &targetInodePtr);
        if (rc != 0) return rc;
        // Never fails except IO
        while (Lookup_File(fs, path, &targetInodePtr, &targetInode) != 0);
    }

    // Open file
    file = Malloc(sizeof(struct GOSFS_File));
    if (file == 0) goto memfail;
    file->inodePtr = targetInodePtr;
    Copy_Inode_Info(file, &targetInode);
    strcpy(file->path, path);
    Mutex_Init(&file->lock);

    *pFile = Allocate_File(ops, 0, targetInode.size, file, mode, mountPoint);
    if (*pFile == 0) goto memfail;
    
    // Let the FS instance manage it
    Add_To_Back_Of_GOSFS_File_List(&fs->filesOpened, file);

    return 0;

memfail:
    rc = ENOMEM;
    return rc;
}

static int Close_File(struct File *file) {
    struct GOSFS *fs = file->mountPoint->fsData;
    struct GOSFS_File *fileInstance = file->fsData;
    
    Remove_From_GOSFS_File_List(&fs->filesOpened, fileInstance);

    Free(fileInstance);

    return 0;
}

static int Stat_File(struct File *file, struct VFS_File_Stat *stat) {
    int rc = 0;
    struct GOSFS_File *fileInstance = file->fsData;

    stat->size = fileInstance->size;
    stat->isDirectory = (fileInstance->flags & GOSFS_DIRENTRY_ISDIRECTORY) != 0;
    stat->isSetuid = (fileInstance->flags & GOSFS_DIRENTRY_SETUID) != 0;
    Copy_ACL(stat->acls, fileInstance->acl);

    return 0;
}

// Directory operations

static int Find_Entry(ulong_t selfPtr, const char *name, ulong_t *pTargetInodePtr, struct GOSFS *fs) {
    int rc = 0;
    GET_INDEX_AND_OFFSET(ulong_t, selfPtr, GOSFS_DIR_ENTRIES_PER_BLOCK);
    struct FS_Buffer *buf = 0;
    struct GOSFS_Dir_Entry selfInode;
    ulong_t targetInodePtr;

    rc = Get_FS_Buffer(fs->cache, fs->inodeTableStart + selfPtrIndex, &buf);
    if (rc != 0) return rc;
    selfInode = *((struct GOSFS_Dir_Entry*) buf->data + selfPtrOffset);
    // Release it to avoid being blocked
    Release_FS_Buffer(fs->cache, buf);

    // Direct
    for (int i = 0; i < GOSFS_NUM_DIRECT_BLOCKS; ++i) {
        rc = Find_Inode_Ptr(selfInode.blockList[i], name, &targetInodePtr, fs);
        if (rc == 0) goto success;
        if (rc == NOT_FOUND) continue;
        if (rc != 0) return rc;
    }

    // Indirect
    for (int i = 0; i < GOSFS_NUM_INDIRECT_BLOCKS; ++i) {
        ulong_t blockPtr = selfInode.blockList[GOSFS_NUM_DIRECT_BLOCKS + i];

        rc = Find_Inode_Ptr_Rec(blockPtr, 1, name, &targetInodePtr, fs);
        if (rc == 0) goto success;
        if (rc == NOT_FOUND) continue;
        if (rc != 0) return rc;
    }

    // 2x-indirect
    for (int i = 0; i < GOSFS_NUM_2X_INDIRECT_BLOCKS; ++i) {
        ulong_t blockPtr =
            selfInode.blockList[GOSFS_NUM_DIRECT_BLOCKS + GOSFS_NUM_INDIRECT_BLOCKS + i];

        rc = Find_Inode_Ptr_Rec(blockPtr, 2, name, &targetInodePtr, fs);
        if (rc == 0) goto success;
        if (rc == NOT_FOUND) continue;
        if (rc != 0) return rc;
    }

    return ENOTFOUND;

success:
    *pTargetInodePtr = targetInodePtr;
    return 0;
}

static int Insert_Entry(ulong_t selfPtr, ulong_t targetPtr, struct GOSFS *fs) {
    int rc = 0;
    GET_INDEX_AND_OFFSET(ulong_t, selfPtr, GOSFS_DIR_ENTRIES_PER_BLOCK);
    struct FS_Buffer *buf = 0;
    struct GOSFS_Dir_Entry *self = 0;

    rc = Get_FS_Buffer(fs->cache, fs->inodeTableStart + selfPtrIndex, &buf);
    if (rc != 0) return rc;
    self = (struct GOSFS_Dir_Entry*) buf->data + selfPtrOffset;

    // Direct
    for (int i = 0; i < GOSFS_NUM_DIRECT_BLOCKS; ++i) {
        ulong_t *pBlockPtr = &self->blockList[i];
        bool ptrIsAbsent = *pBlockPtr == GOSFS_ABSENT_PTR;

        if (ptrIsAbsent) {
            rc = Alloc_Block(fs, pBlockPtr);
            if (rc != 0) goto fail;
        }

        rc = Insert_Ptr(*pBlockPtr, targetPtr, fs);
        // Never fails if new block is allocated
        if (ptrIsAbsent && rc != 0) while (Insert_Ptr(*pBlockPtr, targetPtr, fs) != 0);
        if (rc == NOT_FOUND) continue;
        if (rc != 0) goto fail;

        ++self->size;
        if (ptrIsAbsent) Modify_FS_Buffer(fs->cache, buf);
        Release_FS_Buffer(fs->cache, buf);
        return 0;
    }


    // Indirect
    for (int i = 0; i < GOSFS_NUM_INDIRECT_BLOCKS; ++i) {
        ulong_t *pBlockPtr = &self->blockList[GOSFS_NUM_DIRECT_BLOCKS + i];
        bool ptrIsAbsent = *pBlockPtr == GOSFS_ABSENT_PTR;
        
        if (ptrIsAbsent) {
            rc = Alloc_Block(fs, pBlockPtr);
            if (rc != 0) goto fail;
        }
        
        rc = Insert_Ptr_Rec(*pBlockPtr, targetPtr, 1, fs);
        if (ptrIsAbsent && rc != 0) while (Insert_Ptr_Rec(*pBlockPtr, targetPtr, 1, fs) != 0);
        if (rc == NOT_FOUND) continue;
        if (rc != 0) goto fail;

        ++self->size;
        if (ptrIsAbsent) Modify_FS_Buffer(fs->cache, buf);
        Release_FS_Buffer(fs->cache, buf);
        return 0;
    }

    // 2x-indirect
    for (int i = 0; i < GOSFS_NUM_2X_INDIRECT_BLOCKS; ++i) {
        ulong_t *pBlockPtr =
            &self->blockList[GOSFS_NUM_DIRECT_BLOCKS + GOSFS_NUM_INDIRECT_BLOCKS + i];
        bool ptrIsAbsent = *pBlockPtr == GOSFS_ABSENT_PTR;
        
        if (ptrIsAbsent) {
            rc = Alloc_Block(fs, pBlockPtr);
            if (rc != 0) goto fail;
        }
        
        rc = Insert_Ptr_Rec(*pBlockPtr, targetPtr, 2, fs);
        if (ptrIsAbsent && rc != 0) while (Insert_Ptr_Rec(*pBlockPtr, targetPtr, 2, fs) != 0);
        if (rc == NOT_FOUND) continue;
        if (rc != 0) goto fail;

        ++self->size;
        if (ptrIsAbsent) Modify_FS_Buffer(fs->cache, buf);
        Release_FS_Buffer(fs->cache, buf);
        return 0;
    }

    rc = ENOSPACE;

fail:
    Release_FS_Buffer(fs->cache, buf);
    return rc;
}

static int Delete_Entry(ulong_t selfPtr, ulong_t targetPtr, struct GOSFS *fs) {
    int rc = 0;
    struct FS_Buffer *buf = 0;
    GET_INDEX_AND_OFFSET(ulong_t, selfPtr, GOSFS_DIR_ENTRIES_PER_BLOCK);
    struct GOSFS_Dir_Entry *self = 0;

    rc = Get_FS_Buffer(fs->cache, fs->inodeTableStart + selfPtrIndex, &buf);
    if (rc != 0) return rc;
    self = (struct GOSFS_Dir_Entry*) buf->data + selfPtrOffset;

    // Direct
    for (int i = 0; i < GOSFS_NUM_DIRECT_BLOCKS; ++i) {
        ulong_t *pThisPtr = &self->blockList[i];

        if (*pThisPtr == GOSFS_ABSENT_PTR) continue;

        rc = Delete_Ptr(pThisPtr, targetPtr, fs);
        if (rc == NOT_FOUND) continue;
        if (rc != 0) goto fail;

        if (*pThisPtr == GOSFS_ABSENT_PTR) Modify_FS_Buffer(fs->cache, buf);
        Release_FS_Buffer(fs->cache, buf);
        return 0;
    }

    // Indirect
    for (int i = 0; i < GOSFS_NUM_INDIRECT_BLOCKS; ++i) {
        ulong_t *pThisPtr = &self->blockList[GOSFS_NUM_DIRECT_BLOCKS + i];

        if (*pThisPtr == GOSFS_ABSENT_PTR) continue;

        rc = Delete_Ptr_Rec(pThisPtr, targetPtr, 1, fs);
        if (rc == NOT_FOUND) continue;
        if (rc != 0) goto fail;

        if (*pThisPtr == GOSFS_ABSENT_PTR) Modify_FS_Buffer(fs->cache, buf);
        Release_FS_Buffer(fs->cache, buf);
        return 0;
    }

    // 2x-indirect
    for (int i = 0; i < GOSFS_NUM_2X_INDIRECT_BLOCKS; ++i) {
        ulong_t *pThisPtr =
            &self->blockList[GOSFS_NUM_DIRECT_BLOCKS + GOSFS_NUM_INDIRECT_BLOCKS + i];

        if (*pThisPtr == GOSFS_ABSENT_PTR) continue;

        rc = Delete_Ptr_Rec(pThisPtr, targetPtr, 2, fs);
        if (rc == NOT_FOUND) continue;
        if (rc != 0) goto fail;

        if (*pThisPtr == GOSFS_ABSENT_PTR) Modify_FS_Buffer(fs->cache, buf);
        Release_FS_Buffer(fs->cache, buf);
        return 0;
    }

    Release_FS_Buffer(fs->cache, buf);
    return ENOTFOUND;

fail:
    Release_FS_Buffer(fs->cache, buf);
    return rc;
}

/* ----------------------------------------------------------------------
 * Implementation of VFS operations
 * ---------------------------------------------------------------------- */

/*
 * Get metadata for given file.
 */
static int GOSFS_FStat(struct File *file, struct VFS_File_Stat *stat)
{
    int rc = 0;
    struct GOSFS_File *fileInstance = file->fsData;

    Mutex_Lock(&fileInstance->lock);
    rc = Stat_File(file, stat);
    Mutex_Unlock(&fileInstance->lock);

    return rc;
}

// TODO: what read & write return are HARDCODING now, make
// them the real bytes operated

/*
 * Read data from current position in file.
 */
static int GOSFS_Read(struct File *file, void *buf, ulong_t numBytes)
{
    int rc = 0;
    struct GOSFS *fs = file->mountPoint->fsData;
    struct GOSFS_File *fileInstance = file->fsData;
    ulong_t blockPtr;
    struct FS_Buffer *blockBuf = 0;
    ulong_t numBytesLeft;

    Mutex_Lock(&fileInstance->lock);

    // Reject if no read flag
    if (!(file->mode & O_READ)) {
        Mutex_Unlock(&fileInstance->lock);
        return EACCESS;
    }

    if (file->filePos + numBytes > file->endPos) {
        numBytes = file->endPos - file->filePos;
    }

    // Copy a segment at a time
    numBytesLeft = numBytes;
    while (numBytesLeft != 0) {
        ulong_t posOffset = file->filePos % GOSFS_FS_BLOCK_SIZE;
        ulong_t numBytesThisSeg = MIN(GOSFS_FS_BLOCK_SIZE, posOffset + numBytesLeft) - posOffset;

        rc = Get_Or_Insert_Block_Of_Current_Byte(fileInstance->blockList, file->filePos, &blockPtr, fs);
        if (rc != 0) goto fail;

        rc = Get_FS_Buffer(fs->cache, blockPtr, &blockBuf);
        if (rc != 0) goto fail;

        memcpy(
            (char*) buf + (numBytes - numBytesLeft),
            (char*) blockBuf->data + file->filePos % GOSFS_FS_BLOCK_SIZE,
            numBytesThisSeg
        );
        Release_FS_Buffer(fs->cache, blockBuf);
        file->filePos += numBytesThisSeg;
        numBytesLeft -= numBytesThisSeg;
    }

    Mutex_Unlock(&fileInstance->lock);
    
    return numBytes;

fail:
    Mutex_Unlock(&fileInstance->lock);
    return rc;
}

/*
 * Write data to current position in file.
 */
static int GOSFS_Write(struct File *file, void *buf, ulong_t numBytes)
{
    int rc = 0;
    struct GOSFS *fs = file->mountPoint->fsData;
    struct GOSFS_File *fileInstance = file->fsData;
    ulong_t blockPtr, inodePtr = fileInstance->inodePtr;
    struct FS_Buffer *blockBuf = 0;
    ulong_t numBytesLeft = numBytes;
    struct GOSFS_Dir_Entry *self = 0;

    Mutex_Lock(&fileInstance->lock);

    if (!(file->mode & O_WRITE)) {
        Mutex_Unlock(&fileInstance->lock);
        return EACCESS;
    }

    while (numBytesLeft != 0) {
        ulong_t posOffset = file->filePos % GOSFS_FS_BLOCK_SIZE;
        ulong_t numBytesThisSeg = MIN(GOSFS_FS_BLOCK_SIZE, posOffset + numBytesLeft) - posOffset;

        rc = Get_Or_Insert_Block_Of_Current_Byte(fileInstance->blockList, file->filePos, &blockPtr, fs);
        if (rc != 0) goto fail;

        rc = Get_FS_Buffer(fs->cache, blockPtr, &blockBuf);
        if (rc != 0) goto fail;

        memcpy(
            (char*) blockBuf->data + file->filePos % GOSFS_FS_BLOCK_SIZE,
            (char*) buf + (numBytes - numBytesLeft),
            numBytesThisSeg
        );
        Modify_FS_Buffer(fs->cache, blockBuf);
        Release_FS_Buffer(fs->cache, blockBuf);
        file->filePos += numBytesThisSeg;
        file->endPos += numBytesThisSeg;
        numBytesLeft -= numBytesThisSeg;
    }

    // Synchronize size and block list
    if (fileInstance->size < file->endPos) fileInstance->size = file->endPos;
    GET_INDEX_AND_OFFSET(ulong_t, inodePtr, GOSFS_DIR_ENTRIES_PER_BLOCK);
    rc = Get_FS_Buffer(fs->cache, fs->inodeTableStart + inodePtrIndex, &blockBuf);
    if (rc != 0) goto fail;
    self = (struct GOSFS_Dir_Entry*) blockBuf->data + inodePtrOffset;
    self->size = fileInstance->size;
    memcpy(self->blockList, fileInstance->blockList, GOSFS_NUM_BLOCK_PTRS * sizeof(ulong_t));
    Modify_FS_Buffer(fs->cache, blockBuf);
    Release_FS_Buffer(fs->cache, blockBuf);

    Mutex_Unlock(&fileInstance->lock);

    return numBytes;

fail:
    Mutex_Unlock(&fileInstance->lock);
    return rc;
}

/*
 * Seek to a position in file.
 */
static int GOSFS_Seek(struct File *file, ulong_t pos)
{
    struct GOSFS_File *fileInstance = file->fsData;
    // Print("Seek to %d, endPos: %d\n", pos, file->endPos);
    // We are strict on directories, and reading
    if ((fileInstance->flags & GOSFS_DIRENTRY_ISDIRECTORY || (file->mode & O_READ)) &&
        pos > file->endPos)
        return EINVALID;

    Mutex_Lock(&fileInstance->lock);
    file->filePos = pos;
    if (pos > file->endPos) file->endPos = pos;
    Mutex_Unlock(&fileInstance->lock);

    return 0;
}

/*
 * Close a file.
 */
static int GOSFS_Close(struct File *file)
{
    int rc = 0;
    struct GOSFS_File *fileInstance = file->fsData;

    Mutex_Lock(&fileInstance->lock);
    rc = Close_File(file);
    Mutex_Unlock(&fileInstance->lock);

    return rc;
}

/*static*/ struct File_Ops s_gosfsFileOps = {
    &GOSFS_FStat,
    &GOSFS_Read,
    &GOSFS_Write,
    &GOSFS_Seek,
    &GOSFS_Close,
    0, /* Read_Entry */
};

/*
 * Stat operation for an already open directory.
 */
static int GOSFS_FStat_Directory(struct File *dir, struct VFS_File_Stat *stat)
{
    int rc = 0;
    struct GOSFS_File *fileInstance = dir->fsData;

    Mutex_Lock(&fileInstance->lock);
    rc = Stat_File(dir, stat);
    Mutex_Unlock(&fileInstance->lock);

    return rc;
}

/*
 * Directory Close operation.
 */
static int GOSFS_Close_Directory(struct File *dir)
{
    int rc = 0;
    struct GOSFS_File *fileInstance = dir->fsData;

    Mutex_Lock(&fileInstance->lock);
    rc = Close_File(dir);
    Mutex_Unlock(&fileInstance->lock);

    return rc;
}

/*
 * Read a directory entry from an open directory.
 */
static int GOSFS_Read_Entry(struct File *dir, struct VFS_Dir_Entry *entry)
{
    int rc = 0;
    struct GOSFS_File *fileInstance = dir->fsData;

    Mutex_Lock(&fileInstance->lock);
    do {
        rc = Get_Next_Entry(dir, entry);
    } while (rc == NOT_FOUND);
    Mutex_Unlock(&fileInstance->lock);

    return rc;
}

/*static*/ struct File_Ops s_gosfsDirOps = {
    &GOSFS_FStat_Directory,
    0, /* Read */
    0, /* Write */
    &GOSFS_Seek,
    &GOSFS_Close_Directory,
    &GOSFS_Read_Entry,
};

/*
 * Open a file named by given path.
 */
static int GOSFS_Open(struct Mount_Point *mountPoint, const char *path, int mode, struct File **pFile)
{
    struct GOSFS *fs = mountPoint->fsData;

    Mutex_Lock(&fs->lock);
    int rc = Open_File(mountPoint, path, &s_gosfsFileOps, mode, pFile);
    Mutex_Unlock(&fs->lock);

    return rc;
}

/*
 * Create a directory named by given path.
 */
static int GOSFS_Create_Directory(struct Mount_Point *mountPoint, const char *path)
{
    int rc = 0;
    ulong_t phantomPtr;
    struct GOSFS *fs = mountPoint->fsData;

    Mutex_Lock(&fs->lock);
    rc = Create_File(mountPoint->fsData, path, true, &phantomPtr);
    Mutex_Unlock(&fs->lock);

    return rc;
}

/*
 * Open a directory named by given path.
 */
static int GOSFS_Open_Directory(struct Mount_Point *mountPoint, const char *path, struct File **pDir)
{
    int rc = 0;
    struct GOSFS *fs = mountPoint->fsData;

    Mutex_Lock(&fs->lock);
    rc = Open_File(mountPoint, path, &s_gosfsDirOps, 0, pDir);
    Mutex_Unlock(&fs->lock);

    return rc;
}

/*
 * Delete a directory named by given path.
 */
static int GOSFS_Delete(struct Mount_Point *mountPoint, const char *path)
{
    int rc = 0;
    struct GOSFS *fs = mountPoint->fsData;
    ulong_t inodePtr, dirInodePtr;
    struct GOSFS_Dir_Entry dirInode;
    char *dirPath = 0;

    Mutex_Lock(&fs->lock);

    // Reject if the file is using by other processes
    if (Lookup_Opened(fs, path) != 0) return EACCESS;

    rc = Lookup_File(fs, path, &inodePtr, 0);
    if (rc != 0) goto fail;

    dirPath = Get_Father_Dir_Path(path);
    if (dirPath == 0) goto memfail;
    rc = Lookup_File(fs, dirPath, &dirInodePtr, &dirInode);
    Free(dirPath);
    if (rc != 0) goto fail;

    // Remove the record in father directory's inode
    rc = Delete_Entry(dirInodePtr, inodePtr, fs);
    if (rc != 0) goto fail;
    while (Update_Inode_Cache(fs, dirPath, dirInodePtr) != 0);

    // Clean up resource
    rc = Dealloc_Inode(fs, inodePtr);

    Mutex_Unlock(&fs->lock);

    return rc;

memfail:
    rc = ENOMEM;
fail:
    Mutex_Unlock(&fs->lock);
    return rc;
}

/*
 * Get metadata (size, permissions, etc.) of file named by given path.
 */
static int GOSFS_Stat(struct Mount_Point *mountPoint, const char *path, struct VFS_File_Stat *stat)
{
    int rc = 0;
    struct GOSFS *fs = mountPoint->fsData;
    ulong_t inodePtr;
    struct GOSFS_Dir_Entry inode;

    Mutex_Lock(&fs->lock);
    rc = Lookup_File(fs, path, &inodePtr, &inode);
    if (rc != 0) {
        Mutex_Unlock(&fs->lock);
        return rc;
    }
    Mutex_Unlock(&fs->lock);

    stat->size = inode.size;
    stat->isDirectory = (inode.flags & GOSFS_DIRENTRY_ISDIRECTORY) != 0;
    stat->isSetuid = (inode.flags & GOSFS_DIRENTRY_USED) != 0;
    Copy_ACL(stat->acls, inode.acl);

    return 0;
}

/*
 * Synchronize the filesystem data with the disk
 * (i.e., flush out all buffered filesystem data).
 */
static int GOSFS_Sync(struct Mount_Point *mountPoint)
{
    int rc = 0;
    struct GOSFS *fs = mountPoint->fsData;

    Mutex_Lock(&fs->lock);
    rc = Sync_FS_Buffer_Cache(fs->cache);
    Mutex_Unlock(&fs->lock);

    return rc;
}

/*static*/ struct Mount_Point_Ops s_gosfsMountPointOps = {
    &GOSFS_Open,
    &GOSFS_Create_Directory,
    &GOSFS_Open_Directory,
    &GOSFS_Stat,
    &GOSFS_Sync,
    &GOSFS_Delete,
};

static int GOSFS_Format(struct Block_Device *blockDev)
{
    int rc = 0;
    int numBlocks, numBlockMapBlocks, numInodeTableBlocks;
    // Use a seperate cache because the FS has not been mounted yet
    struct FS_Buffer_Cache *cache = 0;
    struct FS_Buffer *buf = 0;
    struct Super_Block *pSuperBlock = 0, superBlock;

    // Prepare
    numBlocks = Get_Num_Blocks(blockDev) / GOSFS_SECTORS_PER_FS_BLOCK;
    numBlockMapBlocks = numBlocks / GOSFS_NUM_BITS_PER_FS_BLOCK +
        (numBlocks % GOSFS_NUM_BITS_PER_FS_BLOCK != 0);
    numInodeTableBlocks = GOSFS_NUM_INODE_BLOCKS;

    superBlock.magic = GOSFS_MAGIC;
    superBlock.numBlocks = numBlocks;
    superBlock.blockMapStart = GOSFS_BLOCK_MAP_OFFSET;
    superBlock.inodeTableStart = superBlock.blockMapStart + numBlockMapBlocks;
    superBlock.dataBlocksStart = superBlock.inodeTableStart + GOSFS_NUM_INODE_BLOCKS;

    cache = Create_FS_Buffer_Cache(blockDev, GOSFS_FS_BLOCK_SIZE);
    if (cache == 0) {
        rc = ENOMEM;
        goto fail;
    }

    // Super block
    rc = Get_FS_Buffer(cache, GOSFS_SUPERBLOCK_OFFSET, &buf);
    if (rc != 0) goto fail;
    pSuperBlock = (struct Super_Block*) buf->data;
    *pSuperBlock = superBlock;
    Modify_FS_Buffer(cache, buf);

    Release_FS_Buffer(cache, buf);

    // Block bitmap
    for (int i = 0; i < numBlockMapBlocks; ++i) {
        rc = Get_FS_Buffer(cache, superBlock.blockMapStart + i, &buf);
        if (rc != 0) goto fail;

        Clear_Block(buf, cache);
        // Mark the metadata blocks
        if (i == 0) {
            for (int j = 0; j < superBlock.dataBlocksStart; ++j)
                Set_Bit(buf->data, j);
            // We already mark the buffer modified when clearing the block data
        }

        Release_FS_Buffer(cache, buf);
    }

    // Inode table
    for (int i = 0; i < numInodeTableBlocks; ++i) {
        rc = Get_FS_Buffer(cache, superBlock.inodeTableStart + i, &buf);
        if (rc != 0) goto fail;

        Clear_Block(buf, cache);
        // Mark the root directory inode in use
        if (i == 0) {
            struct GOSFS_Dir_Entry *rootDirInode = (struct GOSFS_Dir_Entry*) buf->data + GOSFS_ROOTDIR_INODE_PTR;
            strcpy(rootDirInode->filename, "/");
            rootDirInode->flags |= GOSFS_DIRENTRY_USED | GOSFS_DIRENTRY_ISDIRECTORY;
        }

        Release_FS_Buffer(cache, buf);
    }

    // Print("Format %s with GOSFS successfully\n", blockDev->name);

fail:
    if (Buf_In_Use(buf)) Release_FS_Buffer(cache, buf);
    // We don't synchronize the blocks eagerly to make the operation atomic
    if (cache != 0) Destroy_FS_Buffer_Cache(cache);
    return rc;
}

static int GOSFS_Mount(struct Mount_Point *mountPoint)
{
    int rc = 0;
    struct GOSFS *fs = 0;
    struct FS_Buffer_Cache *cache = 0;
    struct FS_Buffer *buf = 0;
    struct Super_Block *superBlock = 0;

    // The IO cache, it become the FS IO handler later
    cache = Create_FS_Buffer_Cache(mountPoint->dev, GOSFS_FS_BLOCK_SIZE);
    if (cache == 0) goto memfail;

    // Read the super block on disk, fill the FS instance fields
    rc = Get_FS_Buffer(cache, GOSFS_SUPERBLOCK_OFFSET, &buf);
    if (rc != 0) goto fail;
    superBlock = (struct Super_Block*) buf->data;

    if (superBlock->magic != GOSFS_MAGIC) {
        rc = EINVALIDFS;
        goto fail;
    }
    // Yes, it is GOSFS!

    // Instantiate the FS
    mountPoint->fsData = Malloc(sizeof(struct GOSFS));
    if (mountPoint->fsData == 0) goto memfail;
    fs = mountPoint->fsData;
    mountPoint->ops = &s_gosfsMountPointOps;

    // Fill the fileds
    fs->numBlocks = superBlock->numBlocks;
    fs->blockBitmapStart = superBlock->blockMapStart;
    fs->inodeTableStart = superBlock->inodeTableStart;
    fs->dataBlocksStart = superBlock->dataBlocksStart;
    fs->cache = cache;
    Mutex_Init(&fs->lock);
    Clear_GOSFS_File_List(&fs->filesOpened);

    // Print("Mounted %s successfully\n", mountPoint->pathPrefix);
    Release_FS_Buffer(cache, buf);
    return 0;

memfail:
    rc = ENOMEM;
fail:
    if (mountPoint->ops != 0) mountPoint->ops = 0;
    if (fs != 0) {
        Free(fs);
        mountPoint->fsData = 0;
    }
    if (Buf_In_Use(buf)) Release_FS_Buffer(cache, buf);
    if (cache != 0) Destroy_FS_Buffer_Cache(cache);

    return rc;
}

static struct Filesystem_Ops s_gosfsFilesystemOps = {
    &GOSFS_Format,
    &GOSFS_Mount,
};

/* ----------------------------------------------------------------------
 * Public functions
 * ---------------------------------------------------------------------- */

void Init_GOSFS(void)
{
    Register_Filesystem("gosfs", &s_gosfsFilesystemOps);
}

