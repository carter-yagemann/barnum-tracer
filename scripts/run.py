#!/usr/bin/env python

import json
from os import path, listdir, mkdir, getcwd
from shutil import copyfile
import subprocess
import sys
import tempfile
from time import sleep

def sha256(filepath):
    sha256sum = subprocess.Popen(['sha256sum', filepath], stdout=subprocess.PIPE)
    hash = sha256sum.stdout.readline().split(' ')[0]
    sha256sum.terminate()
    return hash

def prepare_jobs(temp_dir):
    jobs = []
    base_img = path.join(getcwd(), 'vm/pt-pdf-base.qcow3')
    nbd_path = '/home/carter/pdf-analysis/kAFL/qemu-2.9.0/qemu-nbd' # TODO - Resolve this instead of hardcoding
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

def run_job(job):
    # TODO - Resolve this instead of hardcoding
    qemu_path = '/home/carter/pdf-analysis/kAFL/qemu-2.9.0/x86_64-softmmu/qemu-system-x86_64'
    nbd_path = '/home/carter/pdf-analysis/kAFL/qemu-2.9.0/qemu-nbd'
    trace_path = 'traces/' + str(job['id'])
    if path.isdir(trace_path):
        print 'VERBOSE: A trace already exists for', job['pdf_name'], 'skipping...'
        return
    print 'VERBOSE: Creating output directory for', job['pdf_name']
    try:
        mkdir(trace_path)
    except:
        print 'ERROR: Failed to create dir', trace_path
        return
    with open(trace_path + '/info.txt', 'w') as info_file:
        info_file.write(job['pdf_name'] + "\n")
    print 'VERBOSE: Starting VM for', job['pdf_name']
    qemu = subprocess.Popen([qemu_path,
                             '-enable-kvm',
                             '-cpu', 'host',
                             '-hda', job['vm_disk'],
                             '-m', '4G',
                             '-balloon', 'virtio',
                             '-vga', 'cirrus',
                             '-vnc', ':0',
                             '-monitor', 'stdio'],
                             stdin=subprocess.PIPE)
    sleep(15) # Give time for Windows VM to boot
    # Pause VM and create a memory dump
    qemu.stdin.write("stop\n")
    qemu.stdin.write("dump-guest-memory " + trace_path + "/dump.qemu\n")
    sleep(20) # Allow time for dump to finish
    # Scan dump to get CR3 using volatility
    cr3 = 0
    pid = 0
    vol = subprocess.Popen(['volatility',
                            'psscan',
                            '--profile', 'Win7SP1x64',
                            '--output=json',
                            '-f', trace_path + '/dump.qemu'],
                            stdout=subprocess.PIPE)
    res = json.loads(vol.stdout.readline())
    vol.terminate()
    for row in res['rows']:
        if row[1] != u'AcroRd32.exe':
            continue
        try:
            pid = row[2]
            cr3 = row[4]
        except:
            print 'ERROR: Could not parse PID and/or CR3 from', row[2], row[4]
            pass
        break
    if cr3 > 0 and pid > 0:
        print 'VERBOSE: Found Acrobat Reader CR3 and PID -', cr3, pid
    else:
        print 'ERROR: Failed to find Acrobat Reader CR3'
        qemu.stdin.write("quit\n")
        qemu.stdin.close()
        return
    # Configure PT
    qemu.stdin.write("pt cr3_filtering 0 " + str(cr3) + "\n")
    qemu.stdin.write("pt set_file " + trace_path + "/trace\n")
    qemu.stdin.write("pt enable 0\n")
    # Resume VM and let Acrobat Reader run
    qemu.stdin.write("cont\n")
    sleep(60)
    # Disable PT and destroy VM
    qemu.stdin.write("pt disable 0\n")
    qemu.stdin.write("pt disable 0\n") # TODO - Workaround for bug in QEMU-PT
    qemu.stdin.write("quit\n")
    qemu.stdin.close()
    # Postmortem analysis
    print 'VERBOSE: Starting postmortem analysis for', job['pdf_name']
    ofile = open('/tmp/dll-list.txt', 'w')
    subprocess.call(['volatility',
                     'ldrmodules',
                     '--profile', 'Win7SP1x64',
                     '-f', trace_path + '/dump.qemu',
                     '-p', str(pid)],
                     stdout=ofile)
    ofile.close()
    mkdir(trace_path + '/mem')
    mkdir('/tmp/mount')
    subprocess.call(['sudo', nbd_path, '--connect=/dev/nbd0', job['base_img'], '-P', '2'])
    subprocess.call(['sudo', 'mount', '/dev/nbd0', '/tmp/mount'])
    gen = subprocess.Popen([getcwd() + '/scripts/gen-mapping.py', '/tmp/mount'], cwd=trace_path + '/mem')
    gen.wait()
    subprocess.call(['sudo', 'umount', '/tmp/mount'])
    subprocess.call(['sudo', nbd_path, '--disconnect', '/dev/nbd0'])
    subprocess.call(['rm', '-rf', '/tmp/mount'])
    subprocess.call(['rm', '/tmp/dll-list.txt'])
    print 'VERBOSE: Merging PT trace with static code for', job['pdf_name']
    subprocess.call(['./tools/bin/pt2griffin',
                     trace_path + '/trace_0',
                     trace_path + '/trace_0.griffin',
                     trace_path + '/mem/mapping.csv'])
    print 'VERBOSE: Disassembling', job['pdf_name']
    disasm = subprocess.Popen([getcwd() + '/tools/bin/disasm', 'trace_0.griffin', 'mem/symbols.csv'], cwd=trace_path)
    disasm.wait()
    print 'VERBOSE: Compressing disassembly for', job['pdf_name']
    subprocess.call(['gzip', trace_path + '/0.txt'])
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
    # TODO - QEMU checks
    return True

if __name__ == '__main__':
    if not perform_checks():
        sys.exit()
    temp_dir = tempfile.mkdtemp()
    jobs = prepare_jobs(temp_dir)
    if len(jobs) < 1:
        print 'ERROR: No jobs found'
        sys.exit()
    for job in jobs:
        run_job(job)
    subprocess.call(['rm', '-rf', temp_dir])
