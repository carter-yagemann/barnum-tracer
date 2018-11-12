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
import os
from shutil import copyfile
import subprocess
import sys
import socket
import tempfile
from time import sleep
import logging
from shutil import copyfile
from struct import pack, unpack
from hashlib import sha256
from optparse import OptionParser, OptionGroup
if sys.version_info.major <= 2:
    from ConfigParser import RawConfigParser, NoOptionError
else:
    from configparser import RawConfigParser, NoOptionError
import pefile

ifup_script = """#!/bin/sh
set -x

switch=$BRIDGE$

if [ -n "$1" ];then
        ip tuntap add $1 mode tap user `whoami`
        ip link set $1 up
        sleep 0.5s
        ip link set $1 master $switch
        exit 0
else
        echo "Error: no interface specified"
        exit 1
fi
"""

def post_processing(vm_disk, maps_fp, partition=2):
    """Performs post-processing on a trace session.

    Specifically, it mounts the VM disk, extracts all the binaries that were loaded during
    execution, expands them into their in-memory layouts, and saves them to the extract directory.

    Keyword Arguments:
    vm_disk -- Filepath to the QCOW2 VM disk.
    maps_fp -- Filepath to maps file.
    partition -- Partition number to mount. 2 by default, which is the norm for Windows 7.

    Returns:
    0 upon success, otherwise a non-zero error code.
    """
    if not os.path.isfile(vm_disk):
        log.error(vm_disk + " is not a file")
        return 2
    if not os.path.isfile(maps_fp):
        log.error(maps_fp + " is not a file")
        return 4

    log.debug("Mounting " + vm_disk)
    nbd_path = lookup_bin('qemu-nbd')
    temp_dir = tempfile.mkdtemp()
    ret = subprocess.call(['sudo', nbd_path, '--connect=/dev/nbd0', vm_disk, '-P', str(partition)])
    if ret != 0:
        log.error('qemu-nbd returned code: ' + str(ret))
        return 1
    ret = subprocess.call(['sudo', 'mount', '-o', 'ro', '/dev/nbd0', temp_dir])
    if ret != 0:
        log.error('mount returned code: ' + str(ret))
        return 3

    log.debug("Parsing " + maps_fp)
    with open(maps_fp) as ifile:
        # Note: we intentionally remove the leading / to make a relative path
        bins = [line[70:].replace('\\', '/').strip() for line in ifile.readlines()
                if len(line) >= 69 and line[69] == "\\"]

    log.debug("Expanding " + str(len(bins)) + " binaries")
    for bin in bins:
        binpath = os.path.join(temp_dir, bin)
        opath = 'extract/' + os.path.basename(binpath)
        if not os.path.isfile(binpath):
            log.debug("Cannot find " + binpath)
            continue
        if os.path.isfile(opath):
            log.debug("Already expanded " + opath + ", skipping")
            continue
        pe = pefile.PE(binpath)
        data = pe.get_memory_mapped_image()
        with open(opath, 'wb') as ofile:
            ofile.write(data)
        pe.close()

    log.debug("Unmounting " + vm_disk)
    ret = 1
    while ret != 0:
        sleep(2)  # Give time for I/O to complete
        ret = subprocess.call(['sudo', 'umount', temp_dir], stdout=DEVNULL, stderr=DEVNULL)
    subprocess.call(['sudo', nbd_path, '--disconnect', '/dev/nbd0'], stdout=DEVNULL, stderr=DEVNULL)
    subprocess.call(['rm', '-rf', temp_dir])

    return 0

def transfer_sample(vm_disk, file_fp, partition=2):
    """Copies the input sample into the guest virtual machine.

    Keyword Arguments:
    vm_disk -- Filepath to the QCOW2 VM disk.
    file_fp -- Path to file to copy over into guest.
    partition -- Partition number to mount. 2 by default, which is the norm for Windows 7.

    Returns:
    0 upon success, otherwise a non-zero error code.
    """
    if not os.path.isfile(file_fp):
        log.error(file_fp + " is not a file")
        return 1
    if not os.path.isfile(vm_disk):
        log.error(vm_disk + " is not a file")
        return 2

    log.debug("Mounting " + vm_disk)
    nbd_path = lookup_bin('qemu-nbd')
    temp_dir = tempfile.mkdtemp()
    ret = subprocess.call(['sudo', nbd_path, '--connect=/dev/nbd0', vm_disk, '-P', str(partition)])
    if ret != 0:
        log.error('qemu-nbd returned code: ' + str(ret))
        return 1
    ret = subprocess.call(['sudo', 'mount', '/dev/nbd0', temp_dir])
    if ret != 0:
        log.error('mount returned code: ' + str(ret))
        return 3

    copyfile(file_fp, temp_dir + "/data")

    log.debug("Unmounting " + vm_disk)
    ret = 1
    while ret != 0:
        sleep(2)  # Give time for I/O to complete
        ret = subprocess.call(['sudo', 'umount', temp_dir], stdout=DEVNULL, stderr=DEVNULL)
    subprocess.call(['sudo', nbd_path, '--disconnect', '/dev/nbd0'], stdout=DEVNULL, stderr=DEVNULL)
    subprocess.call(['rm', '-rf', temp_dir])

    return 0

def watch_file(filepath):
    """Waits until a file stops growing and then returns.

    Keyword Arguments:
    filepath -- The file to watch.
    """
    if not os.path.isfile(filepath):
        log.warning(filepath + " is not a file")
        return
    curr_size = 0
    while True:
        sleep(1)
        new_size = os.path.getsize(filepath)
        if new_size == curr_size:
            break
        curr_size = new_size

def check_qemu_version():
    """Finds QEMU and returns its version.

    Returns:
    True if QEMU version is QEMU-PT, otherwise False.
    """
    qemu_path = lookup_bin('qemu-system-x86_64')
    if qemu_path == '':
        return False
    p = subprocess.Popen([qemu_path, '--version'], stdout=subprocess.PIPE)
    if not 'QEMU-PT' in p.stdout.read():
        return False
    return True

def lookup_bin(name):
    """Finds a program using which."""
    p = subprocess.Popen(['which', name], stdout=subprocess.PIPE)
    return p.stdout.read().strip()

def sha256_file(filepath):
    """Calculates a SHA256 hash of a file's contents.

    Keyword Arguments:
    filepath -- The file whose contents should be hashed.

    Returns:
    A hex digest of the file's contents.
    """
    with open(filepath, 'rb') as ifile:
        data = ifile.read()
    return sha256(data).hexdigest()

def prepare_jobs():
    """Scan the inputs directory and prepare jobs."""
    log.info("Preparing job(s)")
    # Create QEMU ifup script
    ofpath = 'qemu-ifup'
    with open(ofpath, 'w') as ofile:
        ofile.write(ifup_script.replace('$BRIDGE$', conf['bridge']))
    subprocess.call(['chmod', '755', ofpath])

    # Populate jobs list
    jobs = []
    listing = os.listdir('inputs')
    for entry in listing:
        if entry == 'README':
            continue  # Skip the README file
        filepath = 'inputs/' + entry
        id = sha256_file(filepath)
        base_img = os.getcwd() + '/' + options.vm
        jobs.append({'id': id, 'name': entry, 'filepath': filepath, 'vm_disk': None, 'base_img': base_img})

    return jobs, ofpath

def vol_cr3_lookup(qemu, trace_path, proc_name):
    """Dump a QEMU VM's memory and call volatility on it to find the PID and CR3 of a process.

    Keyword Arguments:
    qemu -- The subprocess object representing the running QEMU instance.
    trace_path -- The working directory to store dumps in.
    proc_name -- The VM process to search for.

    Returns:
    (cr3, pid) if found, otherwise (0, 0).
    """
    # Pause VM and create a memory dump
    exec_cmd(qemu, "stop")
    exec_cmd(qemu, "dump-guest-memory " + trace_path + "/dump.qemu")
    watch_file(trace_path + "/dump.qemu")
    subprocess.call(['sudo', 'chmod', 'g+r,o+r', trace_path + "/dump.qemu"])
    # Scan dump to get CR3 using volatility
    cr3 = 0
    pid = 0
    vol = subprocess.Popen(['volatility',
                            'psscan',
                            '--profile', 'Win7SP1x64',
                            '--output=json',
                            '-f', trace_path + '/dump.qemu'],
                            stdout=subprocess.PIPE,
                            stderr=DEVNULL)
    try:
        output = vol.stdout.read()
        log.debug("Volatility ouput: " + output)
        res = json.loads(output)
    except Exception as ex:
        log.error('Failed to read JSON from volatility: ' + str(ex))
        vol.terminate()
        return (0, 0)
    vol.terminate()
    for row in res['rows']:
        if row[1] != proc_name:
            continue
        try:
            pid = row[2]
            cr3 = row[4]
        except:
            log.warning('Could not parse PID and/or CR3 from ' + str(row[2]) + " " + str(row[4]))
        break
    exec_cmd(qemu, "cont")
    if cr3 > 0 and pid > 0:
        log.debug('Found ' + proc_name + ' CR3 and PID - ' + str(cr3) + ' ' + str(pid))
        return (cr3, pid)
    else:
        log.error('Failed to find ' + proc_name + ' CR3')
        return (0, 0)

def exec_cmd(qemu, command):
    """Send a command to a QEMU instance.

    Keyword arguments:
    qemu -- A subprocess object representing a QEMU instance.
    command -- The command string to send.
    """
    qemu.stdin.write(str(command) + "\n")
    qemu.stdout.readline()

def flush_qemu(qemu):
    """Flush QEMU's stdout.

    Keyword Arguments:
    qemu -- A subprocess object representing a QEMU instance.
    """
    char = ''
    while char != ')':
        char = qemu.stdout.read(1)

def terminate_qemu(qemu, force=False):
    """Terminates a QEMU instance.

    Keyword arguments:
    qemu -- A subprocess object representing a QEMU instance.
    force -- If true, will send a SIGTERM if needed.
    """
    qemu.stdin.write("quit\n")
    qemu.stdin.close()
    if force:
        subprocess.call(['sudo', 'kill', '-9', str(qemu.pid)])
    sleep(10)  # Allow time for VM to terminate

def init_socket():
    """Initialize the socket for sending inputs/jobs to the guest VM"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(conf['timeout'])
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((conf['host_ip'], 52175))
    except socket.error:
        log.error("Failed to bind to port")
        return None
    return sock

def send_file(conn, src, isfile=True):
    """ Sends a file or buffer through the connection.

    Keyword Arguments:
    conn -- A connection object created by, for example, socket.accept().
    src -- A string buffer containing the data if isfile is False, otherwise
           the path to a file.
    isfile -- If True, src is a filepath, otherwise src is a buffer.

    Return:
    0 if successful, otherwise an error number.
    """
    if isfile and not os.path.isfile(src):
        log.error(src + " is not a file, nothing to send!")
        return 0

    if isfile:
        with open(src, 'rb') as ifile:
            data = ifile.read()
    else:
        data = src

    checksum = sha256(data).digest()[:4]
    data_size = len(data)
    try:
        conn.sendall(pack('!L4s', data_size, checksum) + data)
    except Exception as ex:
        log.error("Error occurred while trying to send file: " + str(ex))
        return 1

def recv_file(sock):
    """ Recieves a file from the connected socket.

    Keyword Arguments:
    sock -- A connected socket to recieve from.

    Returns:
    Data on success, otherwise None.
    """
    try:
        size, checksum = unpack('!L4s', sock.recv(8))
    except Exception as ex:
        log.error("Error occurred while trying to receive file: " + str(ex))
        return None

    remain = size
    data = ''
    while remain > 0:
        data += sock.recv(min(remain, 1024))
        remain = size - len(data)

    if checksum != sha256(data).digest()[:4]:
        log.error('Checksum does not match')
        return None

    return data

def run_job(job, ifup):
    """ Runs one job.

    Keyword Arguments:
    job -- One item from the output of prepare_jobs(). This is a dictionary.
    sock -- An open socket to listen for agent connections on.
    """
    # Environment checks
    qemu_path = lookup_bin('qemu-system-x86_64')
    nbd_path = lookup_bin('qemu-nbd')
    if len(qemu_path) == 0 or len(nbd_path) == 0:
        log.error('Cannot find qemu-system-x86_64 and/or qemu-nbd')
        return

    sock = init_socket()
    if sock is None:
        log.error("Failed to create socket")
        return

    # Check if output dir already exists, then create
    trace_path = 'traces/' + str(job['id'])
    if os.path.isdir(trace_path) and os.path.isfile(trace_path + '/trace_0.gz'):
        log.warning('A trace already exists for ' + job['name'] + ' skipping...')
        return
    elif os.path.isdir(trace_path):
        log.debug('A trace directory exists for ' + job['name'] + ' but it does not contain a trace')
    else:
        log.debug('Creating output directory for ' + job['name'])
        try:
            os.mkdir(trace_path)
        except:
            log.error('Failed to create dir ' + trace_path)
            return

    # Create info.txt
    with open(trace_path + '/info.txt', 'w') as info_file:
        info_file.write(job['name'] + "\n")
        if options.benign:
            info_file.write("benign\n")
        elif options.malicious:
            info_file.write("malicious\n")
        if options.extra_label:
            info_file.write(options.extra_label + "\n")

    # Create and start snapshot of base VM
    job['vm_disk'] = trace_path + '/disk.qcow2'
    clean_disk = trace_path + '/disk-clean.qcow'  # A second, clean disk for post-processing
    ret = subprocess.call(['qemu-img', 'create', '-f', 'qcow2', '-o', 'backing_file=' + job['base_img'],
                          job['vm_disk']], stdout=DEVNULL)
    if ret != 0:
        log.error('qemu-img return code ' + str(ret))
        subprocess.call(['rm', '-rf', trace_path])
        return
    ret = subprocess.call(['qemu-img', 'create', '-f', 'qcow2', '-o', 'backing_file=' + job['base_img'],
                          clean_disk], stdout=DEVNULL)
    if ret != 0:
        log.error('qemu-img return code ' + str(ret))
        subprocess.call(['rm', '-rf', trace_path])
        return

    transfer_sample(job['vm_disk'], job['filepath'])

    log.debug('Starting VM for ' + job['name'])
    qemu = subprocess.Popen(['sudo', qemu_path,
                             '-enable-kvm',
                             '-cpu', 'host',
                             '-hda', job['vm_disk'],
                             '-m', '2G',
                             '-balloon', 'virtio',
                             '-vga', 'cirrus',
                             '-device', 'e1000,netdev=net0,mac=98:de:d0:04:cb:ff',
                             '-netdev', 'tap,id=net0,script=' + ifup,
                             '-vnc', ':0',
                             '-monitor', 'stdio'],
                             stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE,
                             stderr=DEVNULL)
    flush_qemu(qemu)

    log.info("Waiting for VM agent to call home")
    try:
        sock.listen(0)
        conn, addr = sock.accept()
    except socket.timeout:
        log.error("Did not receive connection from agent within timeout, aborting...")
        terminate_qemu(qemu, True)
        subprocess.call(['rm', '-rf', trace_path])
        return

    log.info("Sending job to " + str(addr[0]))
    if send_file(conn, options.job):
        log.error("Failed to send job, cannot continue")
        terminate_qemu(qemu, True)
        subprocess.call(['rm', '-rf', trace_path])
        return

    # Main command loop
    cr3 = None
    errors = False
    while (True):
        cmd = recv_file(conn)
        if cmd is None:
            log.warning("Failed to recieve data from agent")
            errors = True
            break
        cmd_len = len(cmd)

        if cmd_len >=2 and cmd[:2] == 'pt':
            # Configure PT
            if cr3 is None:
                log.error('Cannot configure PT, CR3 was never found')
                errors = True
                break
            log.debug('Configuring PT...')
            exec_cmd(qemu, "stop")
            exec_cmd(qemu, "pt cr3_filtering 0 " + str(cr3))
            exec_cmd(qemu, "pt set_file " + trace_path + "/trace")
            exec_cmd(qemu, "pt enable 0")
            exec_cmd(qemu, "cont")
            send_file(conn, "OKAY", False)
            break  # We do not accept anymore commands once PT is running

        elif cmd_len >= 3 and cmd[:3] == 'vmi':
            proc_name = cmd.split(' ', 1)[1]
            log.debug('Attempting to extract CR3 and PID for ' + proc_name)
            for attempt in range(1, 4): # Try 3 times to extract CR3
                cr3, pid = vol_cr3_lookup(qemu, trace_path, proc_name)
                if cr3 > 0 and pid > 0:
                    break
                log.warning('Attempt ' + str(attempt) + ' of 3 failed...')
            if cr3 == 0 and pid == 0:
                log.error('Could not find CR3, cannot continue')
                errors = True
                break
            send_file(conn, "OKAY", False)

    sock.close()

    if errors:
        log.error("Errors occurred while running job, destroying VM and output")
        terminate_qemu(qemu, True)
        subprocess.call(['rm', '-rf', trace_path])
        return

    log.info('Executing for ' + str(conf['runtime']) + ' seconds...')
    sleep(int(conf['runtime']))

    # Disable PT and destroy VM
    exec_cmd(qemu, "pt disable 0")
    terminate_qemu(qemu)
    # Postmortem analysis
    log.info('Post-processing ' + job['name'])
    # Extract memory mapping
    maps_filepath = trace_path + '/mapping.txt'
    ofile = open(maps_filepath, 'w')
    subprocess.call(['volatility',
                     'ldrmodules',
                     '--profile', 'Win7SP1x64',
                     '-f', trace_path + '/dump.qemu',
                     '-p', str(pid)],
                     stdout=ofile,
                     stderr=DEVNULL)
    ofile.close()

    res = post_processing(clean_disk, maps_filepath)
    if res != 0:
        log.warning("Post-processing returned an error code: " + str(res))

    # Compress results and delete dump.qemu to save space
    subprocess.call(['gzip', trace_path + '/trace_0'])
    subprocess.call(['gzip', maps_filepath])
    subprocess.call(['rm', '-f', trace_path + '/dump.qemu', job['vm_disk'], clean_disk])
    log.info('Finished ' + job['name'])

def perform_checks():
    """Performs some sanity checks.

    Checks that run.py is executing in the correct working directory and that
    some necessary files and binaries exist.

    Returns:
    True if all checks pass, otherwise False. If return is False, it is not safe
    to proceed with execution.
    """
    # Check that we're in the correct working directory
    o_dirs = ['extract', 'inputs', 'traces']
    for dir in o_dirs:
        if not os.path.isdir(dir):
            log.error('Expected to see ' + dir + ', am I running in the correct working directory?')
            return False
    # Check that we have a network block device for mounting qcows
    if not os.path.exists('/dev/nbd0'):
        log.error('Cannot find QEMU network block device /dev/nbd0, did you run `sudo modprobe nbd`?')
        return False
    if not check_qemu_version():
        log.error('Cannot find QEMU or QEMU version is not QEMU-PT')
        return False
    return True

def parse_conf(conf_path):
    """Parse configuration file"""
    config = RawConfigParser()
    config.read(conf_path)

    try:
        settings = {
            'bridge':   config.get('main', 'bridge'),
            'host_ip':  config.get('main', 'host_ip'),
            'runtime':  config.getint('main', 'runtime'),
            'timeout':  config.getint('main', 'timeout'),
        }
    except (NoOptionError, ValueError) as e:
        log.error('Configuration is missing parameters. See example.conf.')
        sys.exit(4)

    return settings

def parse_args():
    """ Parses the CLI arguments. """
    parser = OptionParser(usage='Usage: %prog [options]')

    pg_trace = OptionGroup(parser, 'Tracing Options')
    pg_trace.add_option('-a', '--agent-conf', action='store', type='str', default='agent/example.conf',
                        help='Agent config file (default: agent/example.conf)')
    pg_trace.add_option('-j', '--job', action='store', type='str', default='jobs/example.job',
                        help='Job script to run (default: jobs/example.job)')
    pg_trace.add_option('-v', '--vm', action='store', type='str', default=None,
                        help='VM to execute inputs in.')
    pg_trace.add_option('-l', '--log-level', action='store', type='int', default=20,
                        help='Logging level (0 to 50, default: 20).')
    parser.add_option_group(pg_trace)

    pg_label = OptionGroup(parser, 'Label Options')
    pg_label.add_option('-b', '--benign', action='store_true', default=False,
                        help='Mark these inputs as benign for Barnum Learner.')
    pg_label.add_option('-m', '--malicious', action='store_true', default=False,
                        help='Mark these inputs as malicious for Barnum Learner.')
    pg_label.add_option('-e', '--extra-label', action='store', default=None,
                        help='Optional extra label string to mark these inputs with (will appear in info.txt).')
    parser.add_option_group(pg_label)

    options, args = parser.parse_args()
    log.setLevel(options.log_level)

    # Input validation
    errors = False
    if not os.path.isfile(options.agent_conf):
        log.error("File not found: " + options.agent_conf)
        errors = True
    if not os.path.isfile(options.job):
        log.error("File not found: " + options.job)
        errors = True
    if not options.vm or not os.path.isfile(options.vm):
        log.error("File not found: " + str(options.vm))
        errors = True
    if not options.benign and not options.malicious:
        log.error("Must set either benign or malicious flag")
        errors = True
    elif options.benign and options.malicious:
        log.error("Cannot set both benign and malicious flags")
        errors = True

    if errors:
        parser.print_help()
        sys.exit(1)

    return options  # We don't expect args, so no point returning them

def main():
    """ Main method. """
    if not perform_checks():
        sys.exit(2)
    jobs, ifup = prepare_jobs()

    jobs_pend = len(jobs)
    if jobs_pend < 1:
        log.error('No jobs found')
        sys.exit(3)
    log.info("Found " + str(jobs_pend) + " job(s)")
    for job in jobs:
        run_job(job, ifup)
        jobs_pend -= 1
        log.info(str(jobs_pend) + ' jobs remaining')

    # Cleanup
    os.remove(ifup)

if __name__ == '__main__':
    DEVNULL = open(os.devnull, 'w')  # Useful for silencing a lot of outputs

    log = logging.getLogger('barnum-tracer')
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter('%(asctime)-15s [%(levelname)s] %(message)s')
    handler.setFormatter(formatter)
    log.addHandler(handler)

    options = parse_args()
    conf = parse_conf(options.agent_conf)
    main()

    DEVNULL.close()
