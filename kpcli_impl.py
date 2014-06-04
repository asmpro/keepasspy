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
    import cmd
    haveReadline = True
except:
    haveReadline = False

# This is temporary development hack.
# Later on libkeepass (including all it's requirements should be installed
#                      in the system, so simple import libkeepass should suffice)
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "libkeepass"))

import libkeepass as kp

# Program version
VERSION="1.03"
DEBUG=1
VERSION_STR='kpcli V{}, written by Uros Juvan <asmpro@gmail.com> 2014'.format(VERSION)

if DEBUG and not haveReadline: print "We do NOT have readline module!"
# If we have readline module, define class used for completing all possible commands
# in the interactive prompt.
if haveReadline:
    class Shell(cmd.Cmd):
        prompt = 'kpcli> '

        FIND_FIELDS = ['username ', 'title ']
        SET_OPTIONS = ['show_passwords_bool ', 'copy_to_clipboard_str ']

        def __init__(self, kdba, file, masterPassword, keyFile, options, completekey='tab', stdin=None, stdout=None):
            cmd.Cmd.__init__(self, completekey, stdin, stdout)
            self.kdba = kdba
            self.masterPassword = masterPassword
            self.keyFile = keyFile
            self.options = options

        def do_version(self, line):
            """version
            Show program name, version and author."""
            print VERSION_STR

        def do_quit(self, line):
            """quit
            Quit shell. Synonym is q command."""
            return True

        def do_q(self, line):
            return self.do_quit(line)

        def do_dump(self, line):
            """dump
            Dump whole database in CSV format. If show_passwords option is set, show passwords as well. Synonym is d command."""
            database_dump(self.kdba[0], self.options['show_passwords_bool'], None, options['copy_to_clipboard_str'])

        def do_d(self, line):
            return self.do_dump(line)

        def do_find(self, params):
            """find <field1> <regex1> [<field2> <regex2> ... ]
            Search database by specified field using regular expression. Synonym is f command."
              Supported fields: title, username"""
            paramsa = params.split()
            if len(paramsa) % 2 != 0: print "You forgot one of the fieldX regexX pairs"
            filters = dict(zip(paramsa[0::2], map(lambda x: re.compile(x, re.I), paramsa[1::2])))
            unknown = set(filters.keys()) - set(["title", "username"])
            if len(unknown) > 0:
                print "Some invalid/unsupported field names have been used ({}) and will be ignored".format(", ".join(unknown))
            database_dump(kdba[0], self.options['show_passwords_bool'], filters, self.options['copy_to_clipboard_str'])

        def do_f(self, params):
            return self.do_find(params)

        def complete_find(self, text, line, begidx, endidx):
            if not text:
                comps = self.FIND_FIELDS[:]
            else:
                comps = [f for f in self.FIND_FIELDS if f.startswith(text)]

            return comps

        def complete_f(self, text, line, begidx, endidx):
            return self.complete_find(text, line, begidx, endidx)

        def do_reload(self, line):
            """reload [file]
            Reload kdb database if kdb file has changed from previous load or if new file is specified as parameter."""
            #!!!
            pass

        def do_get(self, params):
            """get [option]
            Print out all possible options and associated values (or just one if specified as argument)"""
            paramsa = params.split()
            if len(paramsa) == 0:
                for k, v in self.options.iteritems():
                    print "{}\t{}".format(k, v)
            else:
                if self.options.has_key(paramsa[0]):
                    print "{}\t{}".format(paramsa[0], self.options[paramsa[0]])

        def do_set(self, params):
            """set <option> <value>
            Set specified option to the value"""
            paramsa = params.split()
            if len(paramsa) < 1: return
            elif len(paramsa) == 1: value = None
            else: value = paramsa[1]

            if self.options.has_key(paramsa[0]):
                if paramsa[0].endswith("_bool"):
                    if value != None and (value == "0" or value.lower() == "false"): value = None
                    self.options[paramsa[0]] = bool(value)
                elif paramsa[0].endswith("_str"):
                    self.options[paramsa[0]] = value

        def complete_set(self, text, line, begidx, endidx):
            if not text:
                comps = self.SET_OPTIONS[:]
            else:
                comps = [f for f in self.SET_OPTIONS if f.startswith(text)]

            return comps

        def do_EOF(self, line):
            return True

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
    try:
        while waitTime < timeout:
            print "\r{}s".format(waitTime + 1),
            sys.stdout.flush()
            waitTime += 1
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    print ""
    print "Clearing out clipboard..."

    try:
        pipe = subprocess.Popen([prog], stdin=subprocess.PIPE)
        pipe.communicate("")
    except Exception as e:
        print "Unable to copy text to clipboard: {}".format(e)
        return

# Dump the database, optionally limiting output by regexps by fields (filter).
# If showPasswords is true also show passwords in the output.
# If doCopyToClipboard is not None, copy requested field name to clipboard.
# If copyToClipboardTimeout is not None, use it as override timer for copy to clipboard function.
def database_dump(kdb, showPasswords = False, filter = None, doCopyToClipboard = None, copyToClipboardTimeout = None):
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
            if title != None and filter.has_key("title") and filter["title"].search(title) == None: continue
            if username != None and filter.has_key("username") and filter["username"].search(username) == None: continue

        # Print out retrieved data
        print "\"{}\"\t\"{}\"\t\"{}\"\t\"{}\"\t\"{}\"".format(title, username, password, url, notes)

        if isfirst and doCopyToClipboard != None:
            copyText = None
            if doCopyToClipboard == "password":
                copyText = origPassword
            elif doCopyToClipboard == "username":
                copyText = username

            if copyText != None:
                if copyToClipboardTimeout != None: copyToClipboard(copyText, copyToClipboardTimeout)
                else: copyToClipboard(copyText)
        isfirst = False

# Parse command line options
parser = argparse.ArgumentParser()
parser.add_argument('-v', '--version', action='version', version=VERSION_STR)
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
    if args.password: print "Show passwords in clear"
    if args.title != None: print "Show only titles matching regexp '{}'".format(args.title)
    if args.username != None: print "Show only usernames matching regexp '{}'".format(args.username)
    if args.copy != None: print "Copy {} field to clipboard".format(args.copy)
    if interactive: print "Requested interactive shell"

masterPassword = getpass.getpass("Master password: ")
if DEBUG >= 2:
    print "Master password={}".format(masterPassword)

showPasswords = args.password

kdba = [None]
stream = None
try :
    stream = io.open(args.file, 'rb')
    signature = kp.read_signature(stream)
    cls = kp.get_kdb_reader(signature)
    kdba[0] = cls(stream, password=masterPassword, keyfile=args.keyfile)
    kdb = kdba[0]

    if isinstance(kdb, kp.kdb3.KDB3Reader):
        raise Exception("KDB3 (.kdb, KeePass 1.x) database format not supported!")
    elif isinstance(kdb, kp.kdb4.KDB4Reader):
        pass
    else:
        raise Exception("Unknown/unsupported database format implementation in libkeepass!")

    #print kdb.pretty_print()
    if interactive:
        options = { 'show_passwords_bool': showPasswords, 'copy_to_clipboard_str': args.copy }
        Shell(kdba, args.file, masterPassword, args.keyfile, options).cmdloop()
    else:
        filters = {}
        if args.title != None:
            filters['title'] = re.compile(args.title, re.I)
        if args.username != None:
            filters['username'] = re.compile(args.username, re.I)
        database_dump(kdb, showPasswords, filters, args.copy)
except Exception as e:
    print "ERROR: {}".format(e)
    if DEBUG:
        traceback.print_exc(file=sys.stdout)
finally:
    if kdba[0] != None: kdba[0].close()
    if stream != None: stream.close()
