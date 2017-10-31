#ifndef PT_DISASM_ARFF_H
#define PT_DISASM_ARFF_H

#include <stdio.h>
#include <stdint.h>
#include <distorm.h>

void disasm_arff_write_header(FILE *ofile);
void disasm_arff_write_instance(FILE *ofile, _DInst *inst, char *mem_name, unsigned long mem_base, char *symbol);

#endif
