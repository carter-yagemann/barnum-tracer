#include <stdio.h>
#include "disasm_arff.h"

void disasm_arff_write_header(FILE *ofile)
{
    fprintf(ofile, "%% 1. Title: PT Trace\n%%\n");
    fprintf(ofile, "%% 2. Sources:\n");
    fprintf(ofile, "%%      (a) Creator: Carter Yagemann\n");
    fprintf(ofile, "@RELATION pt-trace\n\n");
    fprintf(ofile, "@ATTRIBUTE addr                 NUMERIC\n");
    fprintf(ofile, "@ATTRIBUTE mem-name             STRING\n");
    fprintf(ofile, "@ATTRIBUTE mem-offset           NUMERIC\n");
    fprintf(ofile, "@ATTRIBUTE symbol-name          STRING\n");
    fprintf(ofile, "@ATTRIBUTE size                 NUMERIC\n");
    fprintf(ofile, "@ATTRIBUTE flags                NUMERIC\n");
    fprintf(ofile, "@ATTRIBUTE segment              NUMERIC\n");
    fprintf(ofile, "@ATTRIBUTE base                 NUMERIC\n");
    fprintf(ofile, "@ATTRIBUTE scale                NUMERIC\n");
    fprintf(ofile, "@ATTRIBUTE disp-size            NUMERIC\n");
    fprintf(ofile, "@ATTRIBUTE opcode               NUMERIC\n");
    fprintf(ofile, "@ATTRIBUTE op1-type             NUMERIC\n");
    fprintf(ofile, "@ATTRIBUTE op1-index            NUMERIC\n");
    fprintf(ofile, "@ATTRIBUTE op1-size             NUMERIC\n");
    fprintf(ofile, "@ATTRIBUTE op2-type             NUMERIC\n");
    fprintf(ofile, "@ATTRIBUTE op2-index            NUMERIC\n");
    fprintf(ofile, "@ATTRIBUTE op2-size             NUMERIC\n");
    fprintf(ofile, "@ATTRIBUTE op3-type             NUMERIC\n");
    fprintf(ofile, "@ATTRIBUTE op3-index            NUMERIC\n");
    fprintf(ofile, "@ATTRIBUTE op3-size             NUMERIC\n");
    fprintf(ofile, "@ATTRIBUTE op4-type             NUMERIC\n");
    fprintf(ofile, "@ATTRIBUTE op4-index            NUMERIC\n");
    fprintf(ofile, "@ATTRIBUTE op4-size             NUMERIC\n");
    fprintf(ofile, "@ATTRIBUTE disp                 NUMERIC\n");
    fprintf(ofile, "@ATTRIBUTE unused-prefixes-mask NUMERIC\n");
    fprintf(ofile, "@ATTRIBUTE meta                 NUMERIC\n");
    fprintf(ofile, "@ATTRIBUTE used-registers-mask  NUMERIC\n");
    fprintf(ofile, "@ATTRIBUTE modified-flags-mask  NUMERIC\n");
    fprintf(ofile, "@ATTRIBUTE tested-flags-mask    NUMERIC\n");
    fprintf(ofile, "@ATTRIBUTE undefined-flags-mask NUMERIC\n\n");
    fprintf(ofile, "@DATA\n");
}

void disasm_arff_write_instance(FILE *ofile, _DInst *inst, char *mem_name, unsigned long mem_base, char *symbol)
{
    int index;

    fprintf(ofile, "%lu,", inst->addr);
    mem_name == NULL ? fprintf(ofile, "?,?,") : fprintf(ofile, "'%s',%lu,", mem_name, inst->addr - mem_base);
    symbol == NULL ? fprintf(ofile, "?,") : fprintf(ofile, "'%s',", symbol);
    fprintf(ofile, "%hhu,", inst->size);
    fprintf(ofile, "%hu,", inst->flags);
    fprintf(ofile, "%hhu,", inst->segment);
    fprintf(ofile, "%hhu,", inst->base);
    fprintf(ofile, "%hhu,", inst->scale);
    fprintf(ofile, "%hu,", inst->dispSize);
    fprintf(ofile, "%hu,", inst->opcode);
    for (index = 0; index < 4; index++)
    {
        fprintf(ofile, "%hhu,", inst->ops[index].type);
        fprintf(ofile, "%hhu,", inst->ops[index].index);
        fprintf(ofile, "%hu,", inst->ops[index].size);
    }
    fprintf(ofile, "%lu,", inst->disp);
    // TODO - inst->imm
    fprintf(ofile, "%hu,", inst->unusedPrefixesMask);
    fprintf(ofile, "%hhu,", inst->meta);
    fprintf(ofile, "%hu,", inst->usedRegistersMask);
    fprintf(ofile, "%hhu,", inst->modifiedFlagsMask);
    fprintf(ofile, "%hhu,", inst->testedFlagsMask);
    fprintf(ofile, "%hhu\n", inst->undefinedFlagsMask);
}
