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
import socket
import tempfile
from time import sleep
import logging
from struct import pack, unpack
from optparse import OptionParser, OptionGroup
if sys.version_info.major <= 2:
    from ConfigParser import RawConfigParser, NoOptionError
else:
    from configparser import RawConfigParser, NoOptionError

# TODO - Remove
"""
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
"""

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

def prepare_jobs():
    jobs = []
    listing = listdir('inputs')
    for entry in listing:
        if entry == 'README':
            continue  # Skip the README file
        filepath = 'inputs/' + entry
        id = sha256(filepath)
        base_img = getcwd() + '/' + options.vm
        jobs.append({'id': id, 'name': entry, 'filepath': filepath, 'vm_disk': None, 'base_img': base_img})
    return jobs

def vol_cr3_lookup(qemu, trace_path, proc_name):
    # Pause VM and create a memory dump
    exec_cmd(qemu, "stop")
    exec_cmd(qemu, "dump-guest-memory " + trace_path + "/dump.qemu")
    subprocess.call(['sudo', 'chmod', 'g+r,o+r', trace_path + "/dump.qemu"])
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
            subprocess.call(['sudo', 'kill', '-9', str(qemu.pid)])
        sleep(10)  # TODO - Cleanup - Allow time for VM to terminate

def init_socket():
    """Initialize the socket for sending inputs/jobs to the guest VM"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(conf['timeout'])
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
    if isfile and not path.isfile(src):
        log.error(src + " is not a file, nothing to send!")
        return 0

    if isfile:
        with open(src, 'r') as ifile:
            data = ifile.read()
    else:
        data = src

    data_size = len(data)
    try:
        conn.sendall(pack('!L', data_size) + data)
    except Exception as ex:
        log.error("Error occurred while trying to send file: " + str(ex))
        return 1

def recv_file(sock):
    """ Recieves a file from the connected socket.

    Keyword Arguments:
    sock -- A connected socket to recieve from.
    """
    try:
        size = unpack('!L', sock.recv(4))[0]
    except Exception as ex:
        log.error("Error occurred while trying to receive file: " + str(ex))
        return ''

    remain = size
    data = ''
    while remain > 0:
        data += sock.recv(min(remain, 4096))
        remain = size - len(data)

    return data

def run_job(job, sock):
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

    # Check if output dir already exists, then create
    trace_path = 'traces/' + str(job['id'])
    if path.isdir(trace_path) and path.isfile(trace_path + '/trace_0.gz'):
        log.warning('A trace already exists for ' + job['name'] + ' skipping...')
        return
    elif path.isdir(trace_path):
        log.debug('A trace directory exists for ' + job['name'] + ' but it does not contain a trace')
    else:
        log.debug('Creating output directory for ' + job['name'])
        try:
            mkdir(trace_path)
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
    ret = subprocess.call(['qemu-img', 'create', '-f', 'qcow2', '-o', 'backing_file=' + job['base_img'], job['vm_disk']])
    if ret != 0:
        log.error('qemu-img return code ' + str(ret))
        subprocess.call(['rm', '-rf', trace_path])
        return

    log.debug('Starting VM for ' + job['name'])
    qemu = subprocess.Popen(['sudo', qemu_path,
                             '-enable-kvm',
                             '-cpu', 'host',
                             '-hda', job['vm_disk'],
                             '-m', '2G',
                             '-balloon', 'virtio',
                             '-vga', 'cirrus',
                             '-device', 'e1000,netdev=net0,mac=98:de:d0:04:cb:ff',
                             '-netdev', 'tap,id=net0,script=qemu-ifup',
                             '-vnc', ':0',
                             '-monitor', 'stdio'],
                             stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE)
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

    log.info("Sending job")
    if send_file(conn, options.job):
        log.error("Failed to send job, cannot continue")
        terminate_qemu(qemu, True)
        subprocess.call(['rm', '-rf', trace_path])
        return
    if send_file(conn, job['filepath']):
        log.error("Failed to send input sample, cannot continue")
        terminate_qemu(qemu, True)
        subprocess.call(['rm', '-rf', trace_path])
        return

    # Main command loop
    cr3 = None
    errors = False
    while (True):
        cmd = recv_file(conn)
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

    conn.shutdown(socket.SHUT_RDWR)

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
    log.info('Starting postmortem analysis for ' + job['name'])
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

    # TODO - Extract and expand binaries
    log.warning("Binary extraction and expansion not implemented yet!")

    # Compress results and delete dump.qemu to save space
    subprocess.call(['gzip', trace_path + '/trace_0'])
    subprocess.call(['gzip', maps_filepath])
    subprocess.call(['rm', '-f', trace_path + '/dump.qemu'])
    subprocess.call(['rm', '-f', job['vm_disk']])
    log.info('Finished ' + job['name'])

def perform_checks():
    # Check that we're in the correct working directory
    if not path.isdir('inputs') or not path.isdir('vm'):
        log.error('Inputs and/or vm dir(s) missing, am I running in the correct working directory?')
        return False
    # Check that we have a network block device for mounting qcows
    if not path.exists('/dev/nbd0'):
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
    pg_trace.add_option('-l', '--log-level', action='store', type='int', default=30,
                        help='Logging level (0 to 50, default: 30).')
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
    if not path.isfile(options.agent_conf):
        log.error("File not found: " + options.agent_conf)
        errors = True
    if not path.isfile(options.job):
        log.error("File not found: " + options.job)
        errors = True
    if not options.vm or not path.isfile(options.vm):
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
    sock = init_socket()
    if sock is None:
        log.error("Failed to create socket")
        sys.exit(6)
    jobs = prepare_jobs()

    jobs_pend = len(jobs)
    if jobs_pend < 1:
        log.error('No jobs found')
        sys.exit(3)
    for job in jobs:
        run_job(job, sock)
        jobs_pend -= 1
        log.info(str(jobs_pend) + ' jobs remaining...')

if __name__ == '__main__':
    log = logging.getLogger('barnum-tracer')
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter('%(asctime)-15s [%(levelname)s] %(message)s')
    handler.setFormatter(formatter)
    log.addHandler(handler)

    options = parse_args()
    conf = parse_conf(options.agent_conf)
    main()
