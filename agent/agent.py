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
#
# Parts of this file is copied from Cuckoo Sandbox.
# Copyright (C) 2012-2013 Claudio Guarnieri.
# Copyright (C) 2014-2018 Cuckoo Foundation.
# http://www.cuckoosandbox.org

import random
import re
import os
import socket
import sys
import hashlib
from ctypes import *
from time import sleep
from struct import pack, unpack
from subprocess import call, Popen, check_output

KERNEL32 = windll.kernel32
USER32   = windll.user32

WM_CLOSE                  = 0x00000010
WM_GETTEXT                = 0x0000000D
WM_GETTEXTLENGTH          = 0x0000000E
BM_CLICK                  = 0x000000F5

EnumWindowsProc = WINFUNCTYPE(c_bool, POINTER(c_int), POINTER(c_int))
EnumChildProc = WINFUNCTYPE(c_bool, POINTER(c_int), POINTER(c_int))

RESOLUTION = {
    "x": USER32.GetSystemMetrics(0),
    "y": USER32.GetSystemMetrics(1)
}

def click(hwnd):
    USER32.SetForegroundWindow(hwnd)
    KERNEL32.Sleep(1000)
    USER32.SendMessageW(hwnd, BM_CLICK, 0, 0)

def foreach_child(hwnd, lparam):
    # List of partial buttons labels to click.
    buttons = [
        "yes", "oui",
        "ok",
        "i accept",
        "next", "suivant",
        "new", "nouveau",
        "install", "installer",
        "file", "fichier",
        "run", "start", "marrer", "cuter",
        "extract",
        "i agree", "accepte",
        "enable", "activer", "accord", "valider",
        "don't send", "ne pas envoyer",
        "don't save",
        "continue", "continuer",
        "personal", "personnel",
        "scan", "scanner",
        "unzip", "dezip",
        "open", "ouvrir",
        "close the program",
        "execute", "executer",
        "launch", "lancer",
        "save", "sauvegarder",
        "download", "load", "charger",
        "end", "fin", "terminer",
        "later",
        "finish",
        "end",
        "allow access",
        "remind me later",
        "save", "sauvegarder"
    ]

    # List of complete button texts to click. These take precedence.
    buttons_complete = [
        "&Ja",  # E.g., Dutch Office Word 2013.
    ]

    # List of buttons labels to not click.
    dontclick = [
        "don't run",
        "i do not accept"
    ]

    classname = create_unicode_buffer(50)
    USER32.GetClassNameW(hwnd, classname, 50)

    # Check if the class of the child is button.
    if "button" in classname.value.lower():
        # Get the text of the button.
        length = USER32.SendMessageW(hwnd, WM_GETTEXTLENGTH, 0, 0)
        text = create_unicode_buffer(length + 1)
        USER32.SendMessageW(hwnd, WM_GETTEXT, length + 1, text)

        if text.value in buttons_complete:
            click(hwnd)
            return True

        # Check if the button is set as "clickable" and click it.
        textval = text.value.replace("&", "").lower()
        for button in buttons:
            if button in textval:
                for btn in dontclick:
                    if btn in textval:
                        break
                else:
                    click(hwnd)

    # Recursively search for childs (USER32.EnumChildWindows).
    return True

# Callback procedure invoked for every enumerated window.
# Purpose is to close any office window
def get_office_window(hwnd, lparam):
    if USER32.IsWindowVisible(hwnd):
        text = create_unicode_buffer(1024)
        USER32.GetWindowTextW(hwnd, text, 1024)
        if re.search("- (Microsoft|Word|Excel|PowerPoint)", text.value):
            USER32.SendNotifyMessageW(hwnd, WM_CLOSE, None, None)
    return True

# Callback procedure invoked for every enumerated window.
def foreach_window(hwnd, lparam):
    # If the window is visible, enumerate its child objects, looking
    # for buttons.
    if USER32.IsWindowVisible(hwnd):
        USER32.EnumChildWindows(hwnd, EnumChildProc(foreach_child), 0)
    return True

def move_mouse():
    x = random.randint(0, RESOLUTION["x"])
    y = random.randint(0, RESOLUTION["y"])
    USER32.SetCursorPos(x, y)

def click_mouse():
    # Move mouse to top-middle position.
    USER32.SetCursorPos(RESOLUTION["x"] / 2, 0)
    # Mouse down.
    USER32.mouse_event(2, 0, 0, 0, None)
    KERNEL32.Sleep(50)
    # Mouse up.
    USER32.mouse_event(4, 0, 0, 0, None)

def monkey():
    seconds = 0

    while True:
        if seconds and not seconds % 60:
            USER32.EnumWindows(EnumWindowsProc(get_office_window), 0)

        click_mouse()
        move_mouse()
        USER32.EnumWindows(EnumWindowsProc(foreach_window), 0)

        KERNEL32.Sleep(1000)
        seconds += 1

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
    if isfile and not os.path.isfile(src):
        sys.stderr.write(src + " is not a file, nothing to send!\n")
        return 0

    if isfile:
        with open(src, 'rb') as ifile:
            data = ifile.read()
    else:
        data = src

    checksum = hashlib.sha256(data).digest()[:4]
    data_size = len(data)
    try:
        conn.sendall(pack('!L4s', data_size, checksum) + data)
    except Exception as ex:
        sys.stderr.write("Error occurred while trying to send file: " + str(ex) + "\n")
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
        sys.stderr.write("Error occurred while trying to receive file: " + str(ex) + "\n")
        return None

    remain = size
    data = ''
    while remain > 0:
        data += sock.recv(min(remain, 1024))
        remain = size - len(data)

    if checksum != hashlib.sha256(data).digest()[:4]:
        sys.stderr.write("Checksum does not match\n")
        return None

    return data

def parse_and_exec(sock, job):
    """ Parses and executes a job script.

    Keyword Arguments:
    sock -- An open socket to the server.
    job -- A string buffer containing a job script.
    """
    cmds = job.split("\n")
    for cmd in cmds:
        cmd_len = len(cmd)

        if cmd_len >= 1 and cmd[0] == '#':
            continue  # Comment line

        elif cmd_len >= 4 and cmd[:4] == 'save':
            filepath = cmd.split(' ', 1)[1]
            os.rename("C:\\data", filepath)

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
            monkey()

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
