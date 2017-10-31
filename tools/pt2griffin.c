#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "pt.h"
#include "dump.h"

#define BUFFER_SIZE 4096
unsigned long seq = 0;

void write_griffin_file_header(FILE *ofile)
{
    struct pt_logfile_header f_header =
    {
        MAGIC,
        VERSION
    };

    struct pt_logitem_process p_header =
    {
        {PT_LOGITEM_PROCESS, sizeof(struct pt_logitem_process)},
        0, // tgid
        0  // cmd_size
    };

    struct pt_logitem_thread t_header =
    {
        {PT_LOGITEM_THREAD, sizeof(struct pt_logitem_thread)},
        0, // tgid
        0  // pid
    };

    fwrite(&f_header, sizeof(struct pt_logfile_header), 1, ofile);
    fwrite(&p_header, sizeof(struct pt_logitem_process), 1, ofile);
    fwrite(&t_header, sizeof(struct pt_logitem_thread), 1, ofile);
}

void fill_prev_buffer_header(FILE *ofile, ssize_t sum)
{
    struct pt_logitem_buffer header =
    {
        {PT_LOGITEM_BUFFER, sum + sizeof(struct pt_logitem_buffer)},
        0,   // tgid
        0,   // pid
        seq, // sequence
        sum, // size
    };

    // Parameter sum is the number of bytes written since last buffer header.
    // Seeking backwards sum + size of header will get us to the start of the header.
    fseek(ofile, -sum - sizeof(struct pt_logitem_buffer), SEEK_CUR);
    fwrite(&header, sizeof(struct pt_logitem_buffer), 1, ofile);
    fseek(ofile, 0, SEEK_END);
    seq++;
}

void write_buffer_header(FILE *ofile, ssize_t sum)
{
    if (sum)
    {
        // This isn't the first buffer header, so we need to go back to the
        // previous header and fill in its size field with sum.
        fill_prev_buffer_header(ofile, sum);
    }

    // Create new buffer header (filled in later by fill_prev_buffer_header())
    struct pt_logitem_buffer header =
    {
        {PT_LOGITEM_BUFFER, 0},
        0,
        0,
        0,
        0
    };

    fwrite(&header, sizeof(struct pt_logitem_buffer), 1, ofile);
}

void write_xpages(FILE *ofile, char *mapping_filename)
{
    char *line = NULL;
    size_t size;
    char *comma_pos, *end;
    struct pt_logitem_xpage xpage;
    char buffer[4096];
    FILE *ifile = NULL;
    FILE *mapping = fopen(mapping_filename, "r");
    if (!mapping)
    {
        fprintf(stderr, "Cannot open %s\n", mapping_filename);
        return;
    }

    while (getline(&line, &size, mapping) > 0)
    {
        comma_pos = strchr(line, ',');
        if (!comma_pos)
            continue;

        // Remove trailing whitespace
        end = line + strlen(line) - 1;
        while (end > line && isspace((unsigned char) *end))
            end--;
        *(end + 1) = 0;

        ifile = fopen(comma_pos + 1, "r");
        if (!ifile)
        {
            fprintf(stderr, "Failed to open %s\n", comma_pos + 1);
            continue;
        }

        xpage.header.kind = PT_LOGITEM_XPAGE;
        xpage.tgid = 0;
        xpage.base = strtoul(line, NULL, 10);
        fseek(ifile, 0, SEEK_END);
        xpage.size = ftell(ifile);
        rewind(ifile);
        xpage.header.size = sizeof(struct pt_logitem_xpage) + xpage.size;

        fwrite(&xpage, sizeof(struct pt_logitem_xpage), 1, ofile);

        while ((size = fread(buffer, 1, 4096, ifile)) > 0)
            fwrite(buffer, 1, size, ofile);

        fclose(ifile);
    }
}

int main(int argc, char *argv[])
{
    FILE *ifile, *ofile;
    const unsigned char buffer[BUFFER_SIZE];
    unsigned char *ptr = (unsigned char *) buffer;
    size_t remaining = 0;
    size_t ret = 0;
    int packet_type = PT_PACKET_ERROR;
    unsigned long packet_len = 0;
    ssize_t sum = 0;

    if (argc < 3)
    {
        printf("%s <pt-trace> <output-file> [memory-mapping]\n", argv[0]);
        return EXIT_FAILURE;
    }

    ifile = fopen(argv[1], "r");
    if (!ifile)
    {
        fprintf(stderr, "Failed to open %s\n", argv[1]);
        return EXIT_FAILURE;
    }

    ofile = fopen(argv[2], "wb");
    if (!ofile)
    {
        fprintf(stderr, "Failed to open %s\n", argv[2]);
        return EXIT_FAILURE;
    }

    write_griffin_file_header(ofile);
    if (argc == 4)
        write_xpages(ofile, argv[3]);
    write_buffer_header(ofile, 0);

    while (1)
    {
        // If the buffer has left over unprocessed data, copy it to the front
        if (remaining)
            memcpy((void *) buffer, ptr, remaining);

        ptr = (unsigned char *) buffer + remaining;

        // Fill remaining space in buffer
        ret = fread(ptr, 1, BUFFER_SIZE - remaining, ifile);

        if (!ret && remaining)
        {
            fprintf(stderr, "Cannot parse last %lu bytes\n", remaining);
            fclose(ifile);
            fclose(ofile);
            return EXIT_FAILURE;
        }

        remaining += ret;
        ptr = (unsigned char *) buffer;

        if (!remaining)
            break; // No more data to read

        while (remaining)
        {
            packet_type = pt_get_packet(ptr, remaining, &packet_len);

            if (packet_type == PT_PACKET_ERROR)
            {
                fprintf(stderr, "Failed to decode PT packet @0x%lx\n", sum);
                fill_prev_buffer_header(ofile, sum);
                fclose(ifile);
                fclose(ofile);
                return EXIT_FAILURE;
            }

            if (packet_len > remaining)
                break; // Only part of the packet was fetched, refill the buffer

            if (packet_type == PT_PACKET_NONE)
                break; // Need to refill buffer

            if (packet_type == PT_PACKET_PSB)
            {
                write_buffer_header(ofile, sum);
                sum = 0;
            }

            fwrite(ptr, 1, packet_len, ofile);

            ptr += packet_len;
            remaining -= packet_len;
            sum += packet_len;
        }
    }

    fill_prev_buffer_header(ofile, sum);
    fclose(ifile);
    fclose(ofile);

    return EXIT_SUCCESS;
}
