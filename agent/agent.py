#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2018 Carter Yagemann
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import os
import socket
import sys
from time import sleep
from struct import pack, unpack
from subprocess import call, Popen, check_output

def default_gateway():
    """Gets the default gateway in Windows"""
    res = check_output(['ipconfig']).split('\n')
    gateway = None
    for line in res:
        if 'Default Gateway' in line:
            gateway = line.split(' ')[-1]
            break

    return str(gateway).strip()

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
        log.error("Error occurred while trying to send file: " + str(ex) + "\n")
        return 1

def recv_file(sock):
    """ Recieves a file from the connected socket.

    Keyword Arguments:
    sock -- A connected socket to recieve from.
    """
    try:
        size = unpack('!L', sock.recv(4))[0]
    except Exception as ex:
        sys.stderr.write("Error occurred while trying to receive file: " + str(ex) + "\n")
        sys.exit(3)

    remain = size
    data = ''
    while remain > 0:
        data += sock.recv(min(remain, 4096))
        remain = size - len(data)

    return data

def parse_and_exec(sock, job):
    """ Parses and executes a job script.

    Keyword Arguments:
    sock -- An open socket to the server.
    job -- A string buffer containing a job script.
    """
    cmds = job.split("\n")
    for cmd in cmds:
        sys.stdout.write(cmd + "\n")
        sys.stdout.flush()
        cmd_len = len(cmd)

        if cmd_len >= 1 and cmd[0] == '#':
            continue  # Comment line

        elif cmd_len >= 4 and cmd[:4] == 'save':
            filepath = cmd.split(' ', 1)[1]
            with open(filepath, 'w') as ofile:
                ofile.write(recv_file(sock))

        elif cmd_len >= 4 and cmd[:4] == 'exec':
            call(cmd.split(' ', 1)[1], shell=True)

        elif cmd_len >= 5 and cmd[:5] == 'async':
            Popen(cmd.split(' ', 1)[1], shell=True)

        elif cmd_len >= 2 and cmd[:2] == 'pt':
            send_file(sock, 'pt', False)
            if recv_file(sock) != 'OKAY':
                sys.exit(4)

        elif cmd_len >= 3 and cmd[:3] == 'vmi':
            send_file(sock, 'vmi ' + cmd.split(' ', 1)[1], False)
            if recv_file(sock) != 'OKAY':
                sys.exit(5)

        elif cmd_len >= 5 and cmd[:5] == 'sleep':
            sleep(int(cmd.split(' ')[1]))

        elif cmd_len >= 4 and cmd[:4] == 'wait':
            sys.exit(7)  # TODO - Block until process is created

        elif cmd_len >= 6 and cmd[:6] == 'monkey':
            sys.exit(6)  # TODO - Monkey (scroll, click, etc.)

    sock.shutdown(socket.SHUT_RDWR)

def main():
    sleep(5)  # Give time for network interfaces to come up
    os.chdir(os.path.dirname(os.path.realpath(__file__)))

    gateway = default_gateway()
    if not gateway:
        sys.exit(1)  # Failed to find default gateway

    # Connect to server
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(30)
    try:
        sock.connect((gateway, 52175))
    except socket.timeout:
        sys.exit(2)  # Failed to connect to server

    # Get job script from server and run
    job = recv_file(sock)
    parse_and_exec(sock, job)

if __name__ == '__main__':
    main()
