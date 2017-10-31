#!/usr/bin/env python

from sys import argv
from os import path, getcwd
import pefile

mount_dir = argv[1]
bases = []
files = []

with open('/tmp/dll-list.txt', 'r') as ifile:
    ifile.readline()
    ifile.readline()
    for line in ifile:
        bases.append(int(line[30:48], 16))
        files.append(line[70:].replace('\\', '/').strip())

ofile = open('mapping.csv', 'w')
sfile = open('symbols.csv', 'w')

for offset in range(len(bases)):
    filepath = path.join(mount_dir, files[offset])
    if not path.isfile(filepath):
        print filepath, "doesn't exist"
        continue
    print filepath
    pe = pefile.PE(filepath)
    data = pe.get_memory_mapped_image()
    with open(path.basename(filepath), 'wb') as bin_file:
        bin_file.write(data)
    ofile.write(str(bases[offset]) + ',' + path.join(getcwd(), path.basename(filepath)) + "\n")
    sfile.write('R,' + str(bases[offset]) + ',' + str(bases[offset] + len(data)) + ',' + path.basename(filepath) + "\n")
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if not exp.address is None and not exp.name is None:
                sfile.write('S,' + str(bases[offset] + exp.address) + ',/' + files[offset] + ':' + exp.name + "\n")

ofile.close()
sfile.close()
