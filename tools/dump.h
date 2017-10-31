#ifndef PT_LOGITEM_H
#define PT_LOGITEM_H

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

#endif
