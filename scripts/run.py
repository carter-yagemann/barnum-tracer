#!/usr/bin/env python
#
# Copyright 2018 Carter Yagemann
#
# This file is part of Barnum.
#
# Barnum is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Barnum is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Barnum.  If not, see <https://www.gnu.org/licenses/>.

import json
from os import path, listdir, mkdir, getcwd
from shutil import copyfile
import subprocess
import sys
import tempfile
from time import sleep

def check_qemu_version():
    qemu_path = lookup_bin('qemu-system-x86_64')
    if qemu_path == '':
        return False
    p = subprocess.Popen([qemu_path, '--version'], stdout=subprocess.PIPE)
    if not 'QEMU-PT' in p.stdout.read():
        return False
    return True

def lookup_bin(name):
    p = subprocess.Popen(['which', name], stdout=subprocess.PIPE)
    return p.stdout.read().strip()

def sha256(filepath):
    sha256sum = subprocess.Popen(['sha256sum', filepath], stdout=subprocess.PIPE)
    hash = sha256sum.stdout.readline().split(' ')[0]
    sha256sum.terminate()
    return hash

def prepare_jobs(temp_dir):
    jobs = []
    base_img = path.join(getcwd(), 'vm/pt-pdf-base.qcow3')
    nbd_path = lookup_bin('qemu-nbd')
    if nbd_path == '':
        print 'ERROR: Cannot find qemu-nbd'
        return jobs # Fatal, cannot continue
    if type(temp_dir) != str:
        return jobs
    mkdir(temp_dir + '/mount')
    listing = listdir('pdfs')
    for entry in listing:
        if entry.lower()[-4:] != '.pdf':
            continue # entry doesn't have pdf extension
        print 'VERBOSE: preparing job for', entry
        pdf_filepath = 'pdfs/' + entry
        id = sha256(pdf_filepath)
        # Create VM disk for job
        vm_disk = temp_dir + '/' + str(id) + '.qcow2'
        ret = subprocess.call(['qemu-img', 'create', '-f', 'qcow2', '-o', 'backing_file=' + base_img, vm_disk])
        if ret != 0:
            print 'ERROR: qemu-img return code', ret
            continue
        # Mount disk and insert PDF file
        ret = subprocess.call(['sudo', nbd_path, '--connect=/dev/nbd0', vm_disk, '-P', '2'])
        if ret != 0:
            print 'ERROR: qemu-nbd returned code', ret
            continue
        ret = subprocess.call(['sudo', 'mount', '/dev/nbd0', temp_dir + '/mount'])
        if ret != 0:
            print 'ERROR: mount returned code', ret
            continue
        copyfile(pdf_filepath, temp_dir + '/mount/file.pdf')
        ret = subprocess.call(['sudo', 'umount', temp_dir + '/mount'])
        if ret != 0:
            print 'ERROR: umount returned code', ret
            return jobs # Fatal, cannot continue
        ret = subprocess.call(['sudo', nbd_path, '--disconnect', '/dev/nbd0'])
        if ret != 0:
            print 'ERROR: qemu-nbd returned code', ret
            return jobs # Fatal, cannot continue
        jobs.append({'id': id, 'pdf_name': entry, 'pdf_filepath': pdf_filepath, 'vm_disk': vm_disk, 'base_img': base_img})
    return jobs

def vol_cr3_lookup(qemu, trace_path):
    # Pause VM and create a memory dump
    exec_cmd(qemu, "stop")
    exec_cmd(qemu, "dump-guest-memory " + trace_path + "/dump.qemu")
    # Scan dump to get CR3 using volatility
    cr3 = 0
    pid = 0
    vol = subprocess.Popen(['volatility',
                            'psscan',
                            '--profile', 'Win7SP1x64',
                            '--output=json',
                            '-f', trace_path + '/dump.qemu'],
                            stdout=subprocess.PIPE)
    try:
        res = json.loads(vol.stdout.readline())
    except:
        print 'ERROR: Failed to read JSON from volatility'
        vol.terminate()
        return (0, 0)
    vol.terminate()
    for row in res['rows']:
        if row[1] != u'AcroRd32.exe':
            continue
        try:
            pid = row[2]
            cr3 = row[4]
        except:
            print 'WARNING: Could not parse PID and/or CR3 from', row[2], row[4]
            pass
        break
    exec_cmd(qemu, "cont")
    if cr3 > 0 and pid > 0:
        print 'VERBOSE: Found Acrobat Reader CR3 and PID -', cr3, pid
        return (cr3, pid)
    else:
        print 'ERROR: Failed to find Acrobat Reader CR3'
        return (0, 0)

def exec_cmd(qemu, command):
    qemu.stdin.write(str(command) + "\n")
    sys.stdout.write(qemu.stdout.readline())

def flush_qemu(qemu):
    char = ''
    while char != ')':
        char = qemu.stdout.read(1)
        sys.stdout.write(char)
        sys.stdout.flush()

def terminate_qemu(qemu, force=False):
        qemu.stdin.write("quit\n")
        qemu.stdin.close()
        if force:
            qemu.kill()
        sleep(10) # Allow time for VM to terminate

def run_job(job):
    qemu_path = lookup_bin('qemu-system-x86_64')
    nbd_path = lookup_bin('qemu-nbd')
    if qemu_path == '' or nbd_path == '':
        print 'ERROR: Cannot find qemu-system-x86_64 and/or qemu-nbd'
        return
    trace_path = 'traces/' + str(job['id'])
    if path.isdir(trace_path) and path.isfile(trace_path + '/trace_0.gz'):
        print 'VERBOSE: A trace already exists for', job['pdf_name'], 'skipping...'
        return
    elif path.isdir(trace_path):
        print 'VERBOSE: A trace directory exists for', job['pdf_name'], 'but it does not contain a trace'
    else:
        print 'VERBOSE: Creating output directory for', job['pdf_name']
        try:
            mkdir(trace_path)
        except:
            print 'ERROR: Failed to create dir', trace_path
            return
    with open(trace_path + '/info.txt', 'w') as info_file:
        info_file.write(job['pdf_name'] + "\n")
        if len(sys.argv) > 1:
            info_file.write(sys.argv[1] + "\n")
    print 'VERBOSE: Starting VM for', job['pdf_name']
    qemu = subprocess.Popen([qemu_path,
                             '-enable-kvm',
                             '-cpu', 'host',
                             '-hda', job['vm_disk'],
                             '-m', '2G',
                             '-balloon', 'virtio',
                             '-vga', 'cirrus',
                             '-vnc', ':0',
                             '-monitor', 'stdio'],
                             stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE)
    flush_qemu(qemu)
    sleep(15) # Give time for Windows VM to boot
    print 'VERBOSE: Attempting to extract CR3 and PID for Acrobat Reader'
    for attempt in range(1, 4): # Try 3 times to extract CR3
        cr3, pid = vol_cr3_lookup(qemu, trace_path)
        if cr3 > 0 and pid > 0:
            break
        print 'WARNING: Attempt', attempt, 'of 4 failed...'
    if cr3 == 0 and pid == 0:
        terminate_qemu(qemu, True)
        subprocess.call(['rm', '-rf', trace_path])
        return
    # Configure PT
    print 'VERBOSE: Configuring PT...'
    exec_cmd(qemu, "stop")
    exec_cmd(qemu, "pt cr3_filtering 0 " + str(cr3))
    exec_cmd(qemu, "pt set_file " + trace_path + "/trace")
    exec_cmd(qemu, "pt enable 0")
    # Resume VM and let Acrobat Reader run
    exec_cmd(qemu, "cont")
    print 'VERBOSE: Executing for 1 minute...'
    sleep(60) # trace 1 minute of execution
    # Disable PT and destroy VM
    exec_cmd(qemu, "pt disable 0")
    terminate_qemu(qemu)
    # Postmortem analysis
    print 'VERBOSE: Starting postmortem analysis for', job['pdf_name']
    # Extract memory mapping
    maps_filepath = trace_path + '/mapping.txt'
    ofile = open(maps_filepath, 'w')
    subprocess.call(['volatility',
                     'ldrmodules',
                     '--profile', 'Win7SP1x64',
                     '-f', trace_path + '/dump.qemu',
                     '-p', str(pid)],
                     stdout=ofile)
    ofile.close()
    # Compress results and delete dump.qemu to save space
    subprocess.call(['gzip', trace_path + '/trace_0'])
    subprocess.call(['gzip', maps_filepath])
    subprocess.call(['rm', '-f', trace_path + '/dump.qemu'])
    print 'VERBOSE: Finished', job['pdf_name']

def perform_checks():
    # Check that we're in the correct working directory
    if not path.isdir('scripts') or not path.isdir('pdfs') or not path.isdir('vm'):
        print 'ERROR: scripts and/or pdfs and/or vm dir(s) missing, am I running in the correct working directory?'
        return False
    # Check that we have a network block device for mounting qcows
    if not path.exists('/dev/nbd0'):
        print 'ERROR: Cannot find QEMU network block device /dev/nbd0, did you run `sudo modprobe nbd`?'
        return False
    if not check_qemu_version():
        print 'ERROR: Cannot find QEMU or QEMU version is not QEMU-PT'
        return False
    return True

if __name__ == '__main__':
    if not perform_checks():
        sys.exit()
    if len(sys.argv) < 2:
        res = raw_input("No label set, continue? [y/n]: ").lower()
        if not 'y' in res:
            sys.exit()
    temp_dir = tempfile.mkdtemp()
    jobs = prepare_jobs(temp_dir)
    remaining_jobs = len(jobs)
    if remaining_jobs < 1:
        print 'ERROR: No jobs found'
        sys.exit()
    for job in jobs:
        run_job(job)
        remaining_jobs -= 1
        print 'VERBOSE:', remaining_jobs, 'jobs remaining...'
    subprocess.call(['rm', '-rf', temp_dir])
