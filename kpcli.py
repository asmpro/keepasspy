#!/usr/bin/env python
# coding: utf-8
#
# This is CLI version of keepasspy.
# Written by Uros Juvan <asmpro@gmail.com> 2014.
# 

import os
import sys
import argparse
import getpass
import re
import subprocess
import time

# This is temporary development hack.
# Later on libkeepass (including all it's requirements should be installed
#                      in the system, so simple import libkeepass should suffice)
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "libkeepass"))

import libkeepass as kp

# Program version
VERSION="1.01"
DEBUG=1

# How long to keep password in the clipboard, before emptying it out

# Function to copy given text to clipboard and wait (timeout seconds, before emptying cliboard out)
def copyToClipboard(text, timeout=12):
    if sys.platform == 'linux2':
        prog = 'xclip'
    elif sys.platform in ('win32', 'cygwin'):
        prog = 'clip'
    elif sys.platform == 'darwin':
        prog = 'pbcopy'
    else:
        print "Cannot copy to cliboard: Unknown platform: {}".format(sys.platform)
        return

    # Try to pipe text to prog, else print error
    try:
        pipe = subprocess.Popen([prog], stdin=subprocess.PIPE)
        pipe.communicate(text)
    except Exception as e:
        print "Unable to copy text to clipboard: {}".format(e)
        return

    # Wait for timeout seconds, outputing timeout seconds before clearing clipboard
    waitTime = 0
    while waitTime < timeout:
        print "\r{}s".format(waitTime + 1),
        sys.stdout.flush()
        waitTime += 1
        time.sleep(1)
    print ""
    print "Clearing out clipboard..."

    try:
        pipe = subprocess.Popen([prog], stdin=subprocess.PIPE)
        pipe.communicate("")
    except Exception as e:
        print "Unable to copy text to clipboard: {}".format(e)
        return


# Parse command line options
parser = argparse.ArgumentParser()
parser.add_argument('-v', '--version', action='version', version='%(prog)s V{}'.format(VERSION))
parser.add_argument('-f', '--file', dest='file', nargs='?', default='test.kdbx', help='KDB4 file (.kdbx)')
parser.add_argument('-k', '--keyfile', dest='keyfile', nargs='?', help='Additional keyfile to use as master key')
parser.add_argument('-p', '--password', dest='password', action='store_const', const=True, default=False, help='Shall we show password (if this argument is not given, asterisks are shown instead of password)')
parser.add_argument('-t', '--title', dest='title', nargs='?', help='Optional regex value to filter only required titles')
parser.add_argument('-u', '--username', dest='username', nargs='?', help='Optional regex value to filter only required usernames')
parser.add_argument('-c', '--copy', dest='copy', nargs='?', help='Optional requirement to copy specified field (password) to clipboard (if this function is supported for your OS)')
# Add ability to filter by URL -l and notes -n as well
args = parser.parse_args()

if DEBUG:
    #from pprint import pprint
    #pprint(args)
    print "File={}".format(args.file)
    if args.keyfile != None: print "Keyfile={}".format(args.keyfile)
    if args.password != None: print "Show passwords in clear"
    if args.title != None: print "Show only titles matching regexp '{}'".format(args.title)
    if args.username != None: print "Show only usernames matching regexp '{}'".format(args.username)
    if args.copy != None: print "Copy {} field to clipboard".format(args.copy)

masterPassword = getpass.getpass("Master password: ")
if DEBUG >= 2:
    print "Master password={}".format(masterPassword)

showPasswords = args.password

titleRe = None
if args.title != None:
    titleRe = re.compile(args.title, re.I)

usernameRe = None
if args.username != None:
    usernameRe = re.compile(args.username, re.I)

try :
    with kp.open(args.file, password=masterPassword, keyfile=args.keyfile) as kdb:
        if isinstance(kdb, kp.kdb3.KDB3Reader):
            raise Exception("KDB3 (.kdb, KeePass 1.x) database format not supported!")
        elif isinstance(kdb, kp.kdb4.KDB4Reader):
            pass
        else:
            raise Exception("Unknown/unsupported database format implementation in libkeepass!")

        #print kdb.pretty_print()
        print "Title\tUsername\tPassword\tURL\tNotes"
        isfirst = True
        for elem in kdb.obj_root.iterfind('.//Group/Entry'):
            title = ""
            username = ""
            password = ""
            url = ""
            notes = ""
            for sel in elem.iterfind('./String'):
                key = sel.find('./Key')
                val = sel.find('./Value')
                if key is None or val is None: continue

                if "Title" in key.text: title = val.text
                elif "UserName" in key.text: username = val.text
                elif "Password" in key.text:
                    origPassword = password = val.text
                    if not showPasswords: password = "".join(map(lambda x: "*", password))
                elif "URL" in key.text: url = val.text
                elif "Notes" in key.text: notes = val.text

            # Check if filter allows showing data
            if titleRe != None:
                if titleRe.search(title) == None: continue
            if usernameRe != None:
                if usernameRe.search(username) == None: continue

            # Print out retrieved data
            print "\"{}\"\t\"{}\"\t\"{}\"\t\"{}\"\t\"{}\"".format(title, username, password, url, notes)

            if isfirst and args.copy != None:
                if args.copy == "password":
                    copyToClipboard(origPassword)
            isfirst = False
except Exception as e:
    print "ERROR: {}".format(e)
