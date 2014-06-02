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
import traceback
import io

# Check if we have required Python version
if sys.hexversion < 0x02070000:
    sys.exit("Python 2.7 is required!")

# If available import readline (interactivity depends on it)
try:
    import readline
    haveReadline = True
except:
    haveReadline = False

# This is temporary development hack.
# Later on libkeepass (including all it's requirements should be installed
#                      in the system, so simple import libkeepass should suffice)
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "libkeepass"))

import libkeepass as kp

# Program version
VERSION="1.02"
DEBUG=1

if DEBUG and not haveReadline: print "We do NOT have readline module!"
# If we have readline module, define class used for completing all possible commands
# in the interactive prompt.
if haveReadline:
    class SimpleCompleter(object):
        def __init__(self, options):
            self.options = sorted(options)

        def complete(self, text, state):
            response = None

            if state == 0:
                # This is the first time for this text, so build a match list.
                if text:
                    self.matches = [s for s in self.options if s and s.startswith(text)]
                else:
                    self.matches = self.options[:]

            try:
                response = self.matches[state]
            except IndexError:
                pass

            return response

# Dump the database, optionally limiting output by regexps by fields (filter).
# If showPasswords is true also show passwords in the output.
def database_dump(kdb, showPasswords = False, filter = None):
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
        if filter != None:
            if filter.has_key("title") and filter["title"].search(title) == None: continue
            if filter.has_key("username") and filter["username"].search(username) == None: continue

        # Print out retrieved data
        print "\"{}\"\t\"{}\"\t\"{}\"\t\"{}\"\t\"{}\"".format(title, username, password, url, notes)
    #!!!

# Dispatch command recevied via input.
def dispatch_command(line, kdba, dbFile, masterPassword, keyFile, options):
    lineParts = line.split()
    supportedCommands = ("find", "dump", "reload", "get", "set", "quit")

    if len(lineParts) == 0 or lineParts[0].lower() == "help" or lineParts[0] == "?" or lineParts[0] == "h":
        if len(lineParts) <= 1:
            print " ".join(supportedCommands)
        else:
            arg = lineParts[1].lower()
            if arg == "find" or arg == "f":
                print "find <field1> <regex1> [<field2> <regex2> ... ]\tSearch database by specified field using regular expression"
                print "    Supported fields: title, username"
            elif arg == "dump" or arg == "d":
                print "dump\tDump whole database in CSV format. If show_passwords option is set, show passwords as well"
            elif arg == "reload":
                print "reload\tReload kdb database if kdb file has changed from previous load"
            elif arg == "get":
                print "get [option]\tPrint out all possible options and associated values (or just one if specified as argument)"
            elif arg == "set":
                print "set <option> <value>\tSet specified option to the value"
            elif arg == "quit" or arg == "q":
                print "quit\tQuit interactive shell (shortcut q can be used as well)"
            elif arg == "help" or arg == "h" or arg == "?":
                print "help\tThis help (shortcut ? or h can be used as well)"
    elif lineParts[0].lower() == "dump" or lineParts[0].lower() == "d":
        database_dump(kdba[0], options['show_passwords'])
    elif lineParts[0].lower() == "find" or lineParts[0].lower() == "f":
        if len(lineParts) < 3 or len(lineParts) % 2 != 1:
            print "Invalid usage, see help"
            return
        params = lineParts[1:]
        filters = { x: re.compile(y, re.I) for x in params[0::2] for y in params[1::2] }
        unknown = set(filters.keys()) - set(["title", "username"])
        if len(unknown) > 0:
            print "Some invalid/unsupported field names have been used ({}) and will be ignored".format(", ".join(unknown))
            return
        database_dump(kdba[0], options['show_passwords'], filters)
    #!!!

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
interactive = False
if haveReadline:
    parser.add_argument('-i', '--interactive', dest='interactive', action='store_const', const=True, default=False, help='Should we start interactive shell to operate on open database')
# Add ability to filter by URL -l and notes -n as well
args = parser.parse_args()
if haveReadline and args.interactive: interactive = True

if DEBUG:
    #from pprint import pprint
    #pprint(args)
    print "File={}".format(args.file)
    if args.keyfile != None: print "Keyfile={}".format(args.keyfile)
    if args.password != None: print "Show passwords in clear"
    if args.title != None: print "Show only titles matching regexp '{}'".format(args.title)
    if args.username != None: print "Show only usernames matching regexp '{}'".format(args.username)
    if args.copy != None: print "Copy {} field to clipboard".format(args.copy)
    if interactive: print "Requested interactive shell"

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

kdba = [None]
stream = None
try :
    stream = io.open(args.file, 'rb')
    signature = kp.read_signature(stream)
    cls = kp.get_kdb_reader(signature)
    kdba[0] = cls(stream, password=masterPassword, keyfile=args.keyfile)
    kdb = kdba[0]

    #with kp.open(args.file, password=masterPassword, keyfile=args.keyfile) as kdb:
    if True:
        if isinstance(kdb, kp.kdb3.KDB3Reader):
            raise Exception("KDB3 (.kdb, KeePass 1.x) database format not supported!")
        elif isinstance(kdb, kp.kdb4.KDB4Reader):
            pass
        else:
            raise Exception("Unknown/unsupported database format implementation in libkeepass!")

        #print kdb.pretty_print()
        if interactive:
            readline.set_completer(SimpleCompleter(['find', 'dump', 'reload', 'help', '?', 'get', 'set', 'quit']).complete)
            readline.parse_and_bind("tab: complete")
            line = ''
            options = { 'show_passwords': showPasswords }
            while line != 'quit' and line != 'q':
                try:
                    line = raw_input('kpcli> ')
                except EOFError:
                    break
                dispatch_command(line, kdba, args.file, masterPassword, args.keyfile, options)
                #print "Line={}".format(line)
        else:
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
    if DEBUG:
        traceback.print_exc(file=sys.stdout)
finally:
    if kdba[0] != None: kdba[0].close()
    if stream != None: stream.close()
