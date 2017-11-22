#!/usr/bin/env python

import gzip
import png
import sys
from os import path, listdir
import numpy as np
from multiprocessing import Process, Value, Queue, active_children
from datetime import datetime
import time
import pycuda.gpuarray as gpuarray
import pycuda.driver as cuda
from pycuda.tools import make_default_context

def write_pngs(mapping, out_dir):
    for file in mapping.keys():
        a_gpu = gpuarray.to_gpu(mapping[file])
        png.from_array((a_gpu * 255).get().astype(np.uint8), 'RGB').save(path.join(out_dir, file + '.png'))

def update_mapping(mapping, name, rva, color):
    # Mapping is a RGB "boxed row flat pixel" array representation
    # where row offset is page frame number (pfn) and column is offset.
    # This representation naturally maps to PNG.
    pfn = rva / page_size
    off = rva % page_size
    # Initialize mapping if one doesn't exist for this file
    if not mapping.has_key(name):
        mapping[name] = np.array([np.array([True] * row_size, dtype=bool)], dtype=bool)
    # Make sure array has enough rows
    if len(mapping[name]) < (pfn + 1):
        mapping[name] = np.append(mapping[name], np.full((pfn + 1 - mapping[name].shape[0], row_size), True), 0)
    # Find target pixel and add color
    mapping[name][pfn][off * 3]     *= color[0]
    mapping[name][pfn][off * 3 + 1] *= color[1]
    mapping[name][pfn][off * 3 + 2] *= color[2]
    return mapping

def parse_file(ifilename, color, mapping=None):
    if ifilename[-8:] != '.arff.gz':
        pqueue.put("Require filename to end in .arff.gz\n")
        return mapping
    if mapping is None:
        mapping = {}
    try:
        ifile = gzip.open(ifilename, 'r')
    except:
        pqueue.put('Failed to open ' + ifilename + "\n")
        return mapping
    # Skip ahead to data
    while True:
        line = ifile.readline()
        if line == '':
            pqueue.put("Reached EOF without seeing data\n")
            ifile.close()
            return mapping
        if line.strip() == '@DATA':
            break
    # Parse data
    while True:
        line = ifile.readline().strip()
        if line == '':
            break #EoF
        values = line.split(',')
        if len(values) < 5:
            pqueue.put('Corrupted data line: ' + line + "\n")
            continue
        if len(values[1]) < 2:
            pqueue.put('Data line has no name:' + line + "\n")
            continue
        name = values[1][1:-1]
        try:
            offset = int(values[2], 10)
            size = int(values[4], 10)
        except:
            pqueue.put('Failed to parse offset and/or size from: ' + line + "\n")
            continue
        for num in range(size):
            mapping = update_mapping(mapping, name, offset + num, color)
    ifile.close()
    return mapping

def thread_worker(running, iqueue, oqueue, pqueue):
    while True:
        job = None
        try:
            job = iqueue.get(True, 2)
        except:
            if not running.value:
                return
        if not job is None:
            pqueue.put('Parsing ' + path.basename(job[0]) + "\n")
            start = datetime.now()
            mapping = parse_file(job[0], job[1])
            pqueue.put('Parsed ' + path.basename(job[0]) + " in " + str(datetime.now() - start) + "\n")
            oqueue.put(mapping)

def thread_reducer(active_workers, oqueue, pqueue, odir):
    import pycuda.autoinit
    ctx = make_default_context()
    mapping = {}
    while True:
        new_map = None
        try:
            new_map = oqueue.get(True, 2)
        except:
            if not active_workers.value:
                ctx.pop()
                return
        if not new_map is None:
            start = datetime.now()
            for file in new_map.keys():
                if not file in mapping:
                    mapping[file] = new_map[file]
                else:
                    # Check if array shapes match, otherwise expand
                    if mapping[file].shape[0] < new_map[file].shape[0]:
                        diff = new_map[file].shape[0] - mapping[file].shape[0]
                        mapping[file] = np.append(mapping[file], np.full((diff, row_size), True), 0)
                    if mapping[file].shape[0] > new_map[file].shape[0]:
                        diff = mapping[file].shape[0] - new_map[file].shape[0]
                        new_map[file] = np.append(new_map[file], np.full((diff, row_size), True), 0)
                    # Merge arrays
                    gpu_a = gpuarray.to_gpu(mapping[file])
                    gpu_b = gpuarray.to_gpu(new_map[file])
                    mapping[file] = (gpu_a * gpu_b).get()
            write_pngs(mapping, odir)
            pqueue.put('Merged in ' + str(datetime.now() - start) + "\n")

def flush_stdout():
    try:
        while True:
            sys.stdout.write(pqueue.get_nowait())
    except:
        sys.stdout.flush()

if __name__ == '__main__':
    if len(sys.argv) != 4:
        sys.stdout.write('Usage: ' + sys.argv[0] + ' <input_dir> ' + ' <output_dir> ' + " <num_workers>\n")
        sys.exit(1)
    # Parse parameters
    idir = sys.argv[1]
    odir = sys.argv[2]
    try:
        num_workers = int(sys.argv[3], 10)
    except:
        sys.stdout.write('Failed to parse ' + sys.argv[3] + " as an integer\n")
        sys.exit(1)
    if num_workers < 1:
        sys.stdout.write("Number of workers must be at least 1\n")
        sys.exit(1)
    # Initialization
    page_size = 1024
    row_size = page_size * 3 # Each pixel is 3 numbers: RGB
    max_queue_size = num_workers * 2
    running = Value('b', True, lock=None)
    active_workers = Value('b', True, lock=None)
    iqueue = Queue(max_queue_size)
    oqueue = Queue(max_queue_size)
    pqueue = Queue()
    # Spin up workers
    for id in range(num_workers):
        Process(target=thread_worker, args=(running, iqueue, oqueue, pqueue)).start()
    Process(target=thread_reducer, args=(active_workers, oqueue, pqueue, odir)).start()
    # Iterate files and dispatch jobs
    files = listdir(idir)
    for file in files:
        filepath = path.join(idir, file)
        if not path.isfile(filepath):
            continue
        if not '.arff.gz' == filepath[-8:]:
            continue
        if path.getsize(filepath) < 20480:
            # If file is less than 20KB, most likely something is wrong
            continue
        infopath = filepath.replace('.arff.gz', '.info')
        with open(infopath, 'r') as ifile:
            ifile.readline() # Don't care about PDF name
            label = ifile.readline().strip()
        if label == 'benign':
            iqueue.put((filepath, (False, True, True))) # Cyan
        elif label == 'malicious':
            iqueue.put((filepath, (True, False, True))) # Magenta
        else:
            sys.stdout.write('Unknown label: ' + label + "\n")
        flush_stdout()
    # Signal to workers that no more jobs are coming
    running.value = False
    while len(active_children()) > 1:
        flush_stdout()
        time.sleep(2)
    # Signal to reducer that no more workers are running
    active_workers.value = False
    while len(active_children()) > 0:
        time.sleep(2)
    # One final flush to make sure everything is written to stdout
    flush_stdout()
