all: distorm3
	mkdir -p bin
	gcc -Wall -o bin/pt2griffin pt2griffin.c
	gcc -Wall -I distorm/include -o bin/disasm disasm.c disasm_arff.c distorm/distorm3.a

debug: distorm3
	mkdir -p bin
	gcc -Wall -g -o bin/pt2griffin pt2griffin.c
	gcc -Wall -g -D PT_H_DEBUGGING -I distorm/include -o bin/disasm disasm.c disasm_arff.c distorm/distorm3.a

distorm3:
	make -C distorm/make/linux

.PHONY: astyle

astyle:
	astyle/run.sh

clean:
	rm -f bin/*
