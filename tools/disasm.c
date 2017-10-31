#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/mman.h>
#include <ctype.h>
#include <distorm.h>
#include "uthash.h"
#include "utlist.h"
#include "disasm_arff.h"

FILE *ofile = NULL;

typedef struct
{
    uint64_t addr;
    char *name;
    UT_hash_handle hh;
} symbol_t;

symbol_t *symbols = NULL;

typedef struct mem_region_t
{
    unsigned long start_addr;
    unsigned long end_addr;
    char *name;
    struct mem_region_t *next;
} mem_region_t;

mem_region_t *mem_regions = NULL;

void add_symbol(const char *line)
{
    char *colon_pos, *end;
    size_t name_len;
    symbol_t *symbol;

    colon_pos = strchr(line, ':');
    if (colon_pos)
    {
        name_len = strlen(colon_pos + 1) + 1; // strlen excludes \0
        symbol = (symbol_t *) malloc(sizeof(symbol_t));
        if (!symbol)
            return;
        symbol->addr = strtoul(line, NULL, 10);
        symbol->name = (char *) malloc(name_len);
        if (!symbol->name)
            return;
        strncpy(symbol->name, colon_pos + 1, name_len);
        // Remove trailing whitespace
        end = symbol->name + strlen(symbol->name) - 1;
        while (end > symbol->name && isspace((unsigned char) *end))
            end--;
        *(end + 1) = 0;

        HASH_ADD(hh, symbols, addr, sizeof(uint64_t), symbol);
    }
}

void add_region(const char *line)
{
    char *comma_pos1, *comma_pos2, *end;
    size_t name_len;
    mem_region_t *mem;

    comma_pos1 = strchr(line, ',');
    if (!comma_pos1) return;
    comma_pos2 = strchr(comma_pos1 + 1, ',');
    if (!comma_pos2) return;
    name_len = strlen(comma_pos2 + 1) + 1; // strlen excludes \0
    if (name_len < 1) return;

    mem = (mem_region_t *) malloc(sizeof(mem_region_t));
    if (!mem) return;

    mem->start_addr = strtoul(line, NULL, 10);
    mem->end_addr = strtoul(comma_pos1 + 1, NULL, 10);
    mem->name = (char *) malloc(name_len);
    if (!mem->name) return;
    memset(mem->name, 0, name_len);
    strncpy(mem->name, comma_pos2 + 1, name_len);
    // Remove trailing whitespace
    end = mem->name + strlen(mem->name) - 1;
    while (end > mem->name && isspace((unsigned char) *end))
        end--;
    *(end + 1) = 0;

    LL_APPEND(mem_regions, mem);
}

void lookup_region(const unsigned long addr, unsigned long *base_addr, char **name)
{
    mem_region_t *mem;

    *base_addr = 0;
    *name = NULL;

    LL_FOREACH(mem_regions, mem)
    {
        if (mem->start_addr <= addr && mem->end_addr > addr)
        {
            *base_addr = mem->start_addr;
            *name = mem->name;
            return;
        }
    }
}

void parse_maps(char *maps_filename)
{
    char *line = NULL;
    size_t size;
    FILE *maps = fopen(maps_filename, "r");

    if (!maps)
    {
        printf("Failed to open maps file: %s\n", maps_filename);
        return;
    }

    while (getline(&line, &size, maps) > 0)
    {
        switch (line[0])
        {
            case 'S':
                add_symbol(line + 2);
                break;
            case 'R':
                add_region(line + 2);
                break;
            default:
                break;
        }

        line = NULL;
    }
}

#define ABORT(expr, fmt, ...) \
    do { \
        if (expr) { \
            fprintf(stderr, fmt "\n", ## __VA_ARGS__); \
            exit(0); \
        } \
    } while (0)

enum pt_event_kind
{
    PT_EVENT_NONE,
    PT_EVENT_CALL,
    PT_EVENT_RET,
    PT_EVENT_XBEGIN,
    PT_EVENT_XCOMMIT,
    PT_EVENT_XABORT,
};

struct pt_event
{
    unsigned long addr;
    unsigned long kind;
};

#define MAGIC 0x51C0FFEE
#define VERSION 1

struct pt_logfile_header
{
    unsigned int magic;
    unsigned int version;
};

enum pt_logitem_kind
{
    PT_LOGITEM_BUFFER,
    PT_LOGITEM_PROCESS,
    PT_LOGITEM_THREAD,
    PT_LOGITEM_IMAGE,
    PT_LOGITEM_XPAGE,
    PT_LOGITEM_UNMAP,
    PT_LOGITEM_FORK,
    PT_LOGITEM_SECTION,
    PT_LOGITEM_THREAD_END,
};

struct pt_logitem_header
{
    enum pt_logitem_kind kind;
    unsigned int size;
};

struct pt_logitem_buffer
{
    struct pt_logitem_header header;
    unsigned long tgid;
    unsigned long pid;
    unsigned long sequence;
    unsigned long size;
};

struct pt_logitem_process
{
    struct pt_logitem_header header;
    unsigned long tgid;
    unsigned long cmd_size;
};

struct pt_logitem_thread
{
    struct pt_logitem_header header;
    unsigned long tgid;
    unsigned long pid;
};

struct pt_logitem_image
{
    struct pt_logitem_header header;
    unsigned long tgid;
    unsigned long base;
    unsigned int size;
    unsigned int timestamp;
    unsigned long image_name_length;
};

struct pt_logitem_xpage
{
    struct pt_logitem_header header;
    unsigned long tgid;
    unsigned long base;
    unsigned long size;
};

struct pt_logitem_unmap
{
    struct pt_logitem_header header;
    unsigned long tgid;
    unsigned long base;
};

struct pt_logitem_fork
{
    struct pt_logitem_header header;
    unsigned long parent_tgid;
    unsigned long parent_pid;
    unsigned long child_tgid;
    unsigned long child_pid;
};

#define MIRROR_DISTANCE 0x010000000000
#define MIRROR(addr, level) (((addr) + (level) * MIRROR_DISTANCE) & 0x7fffffffffff)

static inline unsigned long pt_ip_to_code(unsigned long addr)
{
    return MIRROR(addr, 1);
}

static inline unsigned long pt_ip_to_block(unsigned long addr)
{
    return MIRROR((addr) & ~0x7, ((addr) & 0x7) + 2);
}

typedef void *pt_recover_arg;

static inline void pt_on_call(unsigned long addr, pt_recover_arg arg)
{
    // Unused
}

static inline void pt_on_ret(unsigned long addr, pt_recover_arg arg)
{
    // Unused
}

static inline void pt_on_xbegin(pt_recover_arg arg)
{
    // Unused
}

static inline void pt_on_xcommit(pt_recover_arg arg)
{
    // Unused
}

static inline void pt_on_xabort(pt_recover_arg arg)
{
    // Unused
}

static inline void pt_on_mode(int mode_payload, pt_recover_arg arg)
{
    // Unused
}

static inline void pt_on_block(unsigned long addr, pt_recover_arg arg)
{
    symbol_t *query;
    unsigned int next;
    unsigned int n;
    _DInst inst;
    unsigned long mem_base = 0;
    char *mem_name = NULL;
    char *symbol_name = NULL;
    _CodeInfo codeInfo =
    {
        .codeOffset = addr,
        .code = (unsigned char *) pt_ip_to_code(addr),
        .codeLen = 0x7fffffff,
        .dt = Decode64Bits,
        .features = DF_NONE,
    };

    if (!ofile)
    {
#ifdef PT_H_DEBUGGING
        printf("WARNING: No output file, skipping block\n");
#endif
        return;
    }

    // Check if this address matches a known symbol and/or memory region
    HASH_FIND(hh, symbols, &addr, sizeof(uint64_t), query);
    if (query)
        symbol_name = query->name;
    lookup_region(addr, &mem_base, &mem_name);

    // Disassembly loop
    while (1)
    {
        distorm_decompose(&codeInfo, &inst, 1, &n);
        next = codeInfo.nextOffset - codeInfo.codeOffset;
        if (!next)
        {
#ifdef PT_H_DEBUGGING
            printf("WARNING: pt_on_block cannot decode BB 0x%lx, skipping\n", (unsigned long) codeInfo.codeOffset);
#endif
            return; /* Invalid instruction */
        }

        disasm_arff_write_instance(ofile, &inst, mem_name, mem_base, symbol_name);

        codeInfo.code += next;
        codeInfo.codeLen -= next;
        codeInfo.codeOffset += next;

        switch (META_GET_FC(inst.meta))
        {
            case FC_CALL:
            case FC_RET:
            case FC_SYS:
            case FC_UNC_BRANCH:
            case FC_CND_BRANCH:
            case FC_INT:
            case FC_CMOV:
                return; /* End of this basic block */
            default:
                break;
        }
    }
}

#define PT_USE_DISTORM

#include "pt.h"

int main(int argc, char *argv[])
{
    FILE *log;
    size_t len;
    struct pt_logfile_header lhdr;
    struct pt_logitem_header header;
    struct pt_logitem_buffer *buffer;
    struct pt_logitem_xpage *xpage;
    void *addr;
    void *item;
    int i;
#ifdef PT_H_DEBUGGING
    struct pt_logitem_thread *thread;
    struct pt_logitem_process *process;
    struct pt_logitem_fork *fork;
#endif

    ABORT(argc < 2, "./pt log-file [symbols-file]");

    if (argc == 3)
        parse_maps(argv[2]);

    log = fopen(argv[1], "r");
    ABORT(!log, "open %s failed", argv[1]);
    ofile = fopen("0.txt", "w");
    ABORT(!ofile, "open 0.txt failed");
    disasm_arff_write_header(ofile);

    len = fread(&lhdr, 1, sizeof(lhdr), log);
    ABORT(len < sizeof(lhdr), "corrupted log");
    ABORT(lhdr.magic != MAGIC, "unmatched magic");
    ABORT(lhdr.version != VERSION, "unmatched version");

    while ((len = fread(&header, 1, sizeof(header), log)))
    {
        /* undo the seek due to header read */
        fseek(log, -sizeof(header), SEEK_CUR);

        /* allocate memory to store the whole item */
        item = malloc(header.size);
        ABORT(!item, "malloc for item failed");

        /* read in */
        len = fread(item, 1, header.size, log);
        ABORT(len != header.size, "unexpected log ending");

        switch (header.kind)
        {
            case PT_LOGITEM_BUFFER:
                buffer = (struct pt_logitem_buffer *) item;
#ifdef PT_H_DEBUGGING
                printf("buffer: pid=%lu, size=%lu\n", buffer->pid, buffer->size);
#endif
                pt_recover((unsigned char *)(buffer + 1), buffer->size, NULL);
                break;
            case PT_LOGITEM_PROCESS:
#ifdef PT_H_DEBUGGING
                process = (struct pt_logitem_process *) item;
                printf("process: tgid=%lu, cmd=%s\n", process->tgid, (char *)(process + 1));
#endif
                break;
            case PT_LOGITEM_THREAD:
#ifdef PT_H_DEBUGGING
                thread = (struct pt_logitem_thread *) item;
                printf("thread: tgid=%lu, pid=%lu\n", thread->tgid, thread->pid);
#endif
                break;
            case PT_LOGITEM_IMAGE:
                break;
            case PT_LOGITEM_XPAGE:
                xpage = (struct pt_logitem_xpage *) item;
#ifdef PT_H_DEBUGGING
                printf("xpage: tgid=%lu, base=%lx, size=%lx\n", xpage->tgid, xpage->base, xpage->size);
#endif
                for (i = 1; i < 10; i++)
                {
                    addr = mmap((void *) MIRROR(xpage->base, i), xpage->size,
                                PROT_READ | PROT_WRITE, MAP_ANONYMOUS
                                | MAP_PRIVATE | MAP_FIXED, -1, 0);
                    ABORT((unsigned long) addr != MIRROR(xpage->base, i), "mirror failed");
                }
                memcpy((void *) pt_ip_to_code(xpage->base), xpage + 1, xpage->size);
                add_page(xpage->base, xpage->size);
                break;
            case PT_LOGITEM_UNMAP:
                break;
            case PT_LOGITEM_FORK:
#ifdef PT_H_DEBUGGING
                fork = (struct pt_logitem_fork *) item;
                printf("fork: parent=%lu, child=%lu\n", fork->parent_pid, fork->child_pid);
#endif
                break;
            default:
                ABORT(1, "unrecognized item type: %d", header.kind);
        }

        free(item);
    }

    fclose(log);
    fclose(ofile);
}
