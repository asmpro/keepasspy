#!/usr/bin/env python
# coding: utf-8
#
# This is CLI version of keepasspy.
# Written by Uros Juvan <asmpro@gmail.com> 2014-2015.
# 
# V1.20:
# - Added group management (add, modify, delete)
# - Added delete for password entries
#
# TODO:
# - Ask again if exit is really desired, when Ctrl+C in detected in interactive mode
# - Add ability to finely tune random password generation (~) by appending length (i.e.: ~l32) and type of
#   chars to use (a - alpha, n - numeric, s - special (special is follwed by allowed chars, ending with 's'),
#   i.e.: ~ans_-!#$s denoting alphanumeric chars and special chars '_-!#$')
# - Add ability to create new kdbx files

import os
import sys
import argparse
import getpass
import re
import subprocess
import time
import traceback
import io
import base64
import uuid
import datetime
import random
import string
from lxml import etree

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
VERSION="1.20"
DEBUG=1
VERSION_STR='kpcli V{}, written by Uros Juvan <asmpro@gmail.com> 2014-2015'.format(VERSION)

# Password generator default values (this may be configurable in the future)
RANDOM_PASS_CHARS="{}{}-_".format(string.ascii_letters, string.digits)
RANDOM_PASS_LENGTH=20

if DEBUG and not haveReadline: print "We do NOT have readline module!"

def parse_field_value(params, keyLower=False, regexVal=True):
    """Parse "field value" params and return dict, where fields are keys, and value values.

    field is always a word without a space.
    value can be a word without a space or multiword enclosed in single or double quotes, i.e.: "test me"
    If None is specified without quotes, set value to None
    If keyLower is True also make all keys lowercase"""

    ret = {}
    if params is None: return ret

    state = 0
    idx = 0
    key = None
    while idx < len(params):
        if state == 0:
            cidx = params.find(" ", idx)
            if cidx == -1: break
            if keyLower:
                key = params[idx:cidx].lower()
            else:
                key = params[idx:cidx]
            idx = cidx + 1
            state = 1
        elif state == 1:
            if params[idx] == '"' or params[idx] == "'":
                quoteChar = params[idx]
                endQuoteIdx = params.find(quoteChar, idx + 1)
                if endQuoteIdx == -1: break
                value = params[idx + 1:endQuoteIdx]
                idx = endQuoteIdx + 2
            else:
                cidx = params.find(" ", idx)
                if cidx == -1: cidx = len(params)
                value = params[idx:cidx]
                if value == "None": value = None
                idx = cidx + 1
            if value == None: ret[key] = None
            else:
                if regexVal: ret[key] = re.compile(value, re.I)
                else: ret[key] = value
            state = 0

    return ret

# If we have readline module, define class used for completing all possible commands
# in the interactive prompt.
if haveReadline:
    class Shell(cmd.Cmd):
        prompt = 'kpcli> '

        FIND_FIELDS = ['username ', 'title ', 'url ', 'uuid ', 'groupname ', 'groupuuid ']
        MODIFY_FIELDS = ['username ', 'title ', 'url ', 'password ', 'notes ']
        SET_OPTIONS = ['show_passwords_bool ', 'copy_to_clipboard_str ']
        MODIFY_GROUP_FIELDS = ['name ', 'notes ', 'iconid ',]

        def __init__(self, kdba, dbFile, masterPassword, keyFile, options, completekey='tab', stdin=None, stdout=None):
            cmd.Cmd.__init__(self, completekey, stdin, stdout)
            self.kdba = kdba
            self.dbFile = dbFile
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

        def do_dumpgroups(self, line):
            """dumpgroups
            Synonym for groupsdump"""
            self.do_groupsdump(line)

        def do_gd(self, line):
            self.do_groupsdump(line)

        def do_groupsdump(self, line):
            """groupsdump
            Dump all the groups, including their UUIDs.
            Usefull for add new entry command, whe group UUID is needed."""
            database_group_dump(self.kdba[0])

        def do_groupadd(self, params):
            """add <parent_group_uuid> <key1> <value1> [key1 value2 [ ... ]]
            Add new group under group specified by group_uuid (If None, create root group if non-existent).
            Key may be one of supported fields (name, notes, iconid).
            default iconid is 49 (General)"""
            idx = params.find(" ")
            if idx == -1:
                print "ERROR: parent_group_uuid missing"
                return
            uuid = params[0:idx]
            if (uuid.startswith('"') and uuid.endswith('"')) or \
               (uuid.startswith("'") and uuid.endswith("'")): uuid = uuid[1:-1]
            keyVals = parse_field_value(params[idx:].strip(), keyLower=True, regexVal=False)
            unknown = set(keyVals.keys()) - set(["name", "notes", "iconid"])
            if len(unknown) > 0:
                print "ERROR: Some invalid/unsupported keys have been used ({})".format(", ".join(unknown))
                return
            if len(keyVals) == 0:
                print "ERROR: At least one key/value must be specified"
                return
            keyVals['parent_group_uuid'] = uuid
            retuuid = database_add_modify_group(kdba[0], keyVals)
            if retuuid != None:
                self.prompt = "*kpcli> "
                print "Added new group with UUID {}".format(retuuid)

        def complete_groupadd(self, text, line, begidx, endidx):
            if not text:
                comps = self.MODIFY_GROUP_FIELDS[:]
            else:
                comps = [f for f in self.MODIFY_GROUP_FIELDS if f.startswith(text)]

            return comps

        def do_ga(self, line):
            """ga
            Synonym for groupadd"""
            self.do_groupadd(line)

        def complete_ga(self, text, line, begidx, endidx):
            return self.complete_groupadd(text, line, begidx, endidx)

        def do_groupmodify(self, params):
            """groupmodify <group_uuid> <key1> <value1> [key1 value2 [ ... ]]
            Modify existing group fields specified by uuid.
            Key may be one of supported fields (name, notes, iconid)."""
            idx = params.find(" ")
            if idx == -1:
                print "ERROR: uuid missing"
                return
            uuid = params[0:idx]
            if (uuid.startswith('"') and uuid.endswith('"')) or \
               (uuid.startswith("'") and uuid.endswith("'")): uuid = uuid[1:-1]
            keyVals = parse_field_value(params[idx:].strip(), keyLower=True, regexVal=False)
            unknown = set(keyVals.keys()) - set(["name", "notes", "iconid"])
            if len(unknown) > 0:
                print "ERROR: Some invalid/unsupported keys have been used ({})".format(", ".join(unknown))
                return
            if len(keyVals) == 0:
                print "ERROR: At least one key/value must be specified"
                return
            keyVals['uuid'] = uuid
            retuuid = database_add_modify_group(kdba[0], keyVals)
            if retuuid != None:
                self.prompt = "*kpcli> "
                print "Modified group with UUID {}".format(retuuid)

        def complete_groupmodify(self, text, line, begidx, endidx):
            if not text:
                comps = self.MODIFY_GROUP_FIELDS[:]
            else:
                comps = [f for f in self.MODIFY_GROUP_FIELDS if f.startswith(text)]

            return comps

        def do_gm(self, line):
            """gm
            Synonym for groupmodify"""
            self.do_groupmodify(line)

        def complete_gm(self, text, line, begidx, endidx):
            return self.complete_groupadd(text, line, begidx, endidx)

        def do_pprint(self, line):
            """pprint
            Pretty print out database to stdout"""
            print kdba[0].pretty_print()

        def do_find(self, params):
            """find <field1> <regex1> [<field2> <regex2> ... ]
            Search database by specified field using regular expression. Synonym is f command."
              Supported fields: title, username, url, uuid, groupname, groupuuid"""
            filters = parse_field_value(params, keyLower=True)
            unknown = set(filters.keys()) - set(["title", "username", "uuid", "url", "groupname", "groupuuid"])
            if len(unknown) > 0:
                print "WARNING: Some invalid/unsupported field names have been used ({}) and will be ignored".format(", ".join(unknown))
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

        def do_reload(self, params):
            """reload [-p] [dbFile [keyFile] ]
            Reload kdb database if kdb file has changed from previous load or if new file is specified as parameter."""
            flds = params.split()
            if len(flds) > 0 and flds[0] == "-p":
                self.masterPassword = getpass.getpass("Master password: ")
                del flds[0]
            if len(flds) > 0:
                self.dbFile = flds[0]
                if len(flds) > 1: self.keyFile = flds[1]

            stream = None
            try:
                stream = io.open(self.dbFile, 'rb')
                signature = kp.read_signature(stream)
                cls = kp.get_kdb_reader(signature)
                self.kdba[0] = cls(stream, password=self.masterPassword, keyfile=self.keyFile)
                self.prompt = "kpcli> "
            except Exception as e:
                print "ERROR: Unable to reload kdbX file {}: {}".format(self.dbFile, e)
            finally:
                if stream != None: stream.close()

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

            # Also show read only options (dbFile and keyFile locations)
            print "\nRead Only options:"
            print "dbFile\t{}".format(self.dbFile)
            print "keyFile\t{}".format(self.keyFile)

        def complete_get(self, text, line, begidx, endidx):
            if not text:
                comps = self.SET_OPTIONS[:]
            else:
                comps = [f for f in self.SET_OPTIONS if f.startswith(text)]

            return comps

        def do_set(self, params):
            """set <option> <value>
            Set specified option to the value:

            option may be one of:
              show_passwords_bool: Should we show passwords in clear? true (1) or false (0)
              copy_to_clipboard_str: What field should we copy to clipboard (password, username or url)"""
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

        def do_write(self, params):
            """write [-p] [dbFile [keyfile] ]
            Write current in memory representation of data to output kdbX file.
            Optional dbFile and of course keyfile may be specified to override current dbFile and keyfile.
            If -p flag is specified also ask for new master password before writing new dbFile.
            """
            flds = params.split()
            if len(flds) > 0 and flds[0] == "-p":
                self.masterPassword = getpass.getpass("Master password: ")
                del flds[0]
            if len(flds) > 0:
                self.dbFile = flds[0]
                if len(flds) > 1: self.keyFile = flds[1]

            # Try to write data to output file
            try:
                with open(self.dbFile, "wb") as fout:
                    credentials = { 'password': self.masterPassword }
                    if self.keyFile != None: credentials['keyfile'] = self.keyFile
                    self.kdba[0].clear_credentials()
                    self.kdba[0].add_credentials(**credentials)
                    self.kdba[0].write_to(fout)
                    self.kdba[0].unprotect()
                    self.prompt = "kpcli> "
            except Exception as e:
                print "ERROR: Unable to write back file {}: {}".format(self.dbFile, e)

        def do_modify(self, params):
            """modify <uuid> <key1> <value1> [key1 value2 [ ... ]]
            Modify existing entry fields specified by uuid.
            Key may be one of supported fields (title, username, password, url, notes).
            You can request random password by specifying ~ instead of pass"""
            idx = params.find(" ")
            if idx == -1:
                print "ERROR: uuid missing"
                return
            uuid = params[0:idx]
            if (uuid.startswith('"') and uuid.endswith('"')) or \
               (uuid.startswith("'") and uuid.endswith("'")): uuid = uuid[1:-1]
            keyVals = parse_field_value(params[idx:].strip(), keyLower=True, regexVal=False)
            unknown = set(keyVals.keys()) - set(["title", "username", "password", "url", "notes"])
            if len(unknown) > 0:
                print "ERROR: Some invalid/unsupported keys have been used ({})".format(", ".join(unknown))
                return
            if len(keyVals) == 0:
                print "ERROR: At least one key/value must be specified"
                return
            keyVals['uuid'] = uuid
            retuuid = database_add_modify(kdba[0], keyVals)
            if retuuid != None:
                self.prompt = "*kpcli> "
                print "Modified UUID {}".format(retuuid)

        def complete_modify(self, text, line, begidx, endidx):
            if not text:
                comps = self.MODIFY_FIELDS[:]
            else:
                comps = [f for f in self.MODIFY_FIELDS if f.startswith(text)]

            return comps

        def do_add(self, params):
            """add <group_uuid> <key1> <value1> [key1 value2 [ ... ]]
            Add new entry under group specified by group_uuid.
            Key may be one of supported fields (title, username, password, url, notes).
            You can request random password by specifying ~ instead of pass"""
            idx = params.find(" ")
            if idx == -1:
                print "ERROR: group_uuid missing"
                return
            uuid = params[0:idx]
            if (uuid.startswith('"') and uuid.endswith('"')) or \
               (uuid.startswith("'") and uuid.endswith("'")): uuid = uuid[1:-1]
            keyVals = parse_field_value(params[idx:].strip(), keyLower=True, regexVal=False)
            unknown = set(keyVals.keys()) - set(["title", "username", "password", "url", "notes"])
            if len(unknown) > 0:
                print "ERROR: Some invalid/unsupported keys have been used ({})".format(", ".join(unknown))
                return
            if len(keyVals) == 0:
                print "ERROR: At least one key/value must be specified"
                return
            keyVals['group_uuid'] = uuid
            retuuid = database_add_modify(kdba[0], keyVals)
            if retuuid != None:
                self.prompt = "*kpcli> "
                print "Added new entry with UUID {}".format(retuuid)

        def complete_add(self, text, line, begidx, endidx):
            if not text:
                comps = self.MODIFY_FIELDS[:]
            else:
                comps = [f for f in self.MODIFY_FIELDS if f.startswith(text)]

            return comps

        def do_delete(self, params):
            """delete <uuid>
            Delete entry specified by UUID.
            """
            uuid = params
            if (uuid.startswith('"') and uuid.endswith('"')) or \
               (uuid.startswith("'") and uuid.endswith("'")): uuid = uuid[1:-1]
            ret = database_delete(kdba[0], uuid)
            if ret == 0:
                self.prompt = "*kpcli> "
                print "Successfully deleted entry with UUID {}".format(uuid)
            else:
                print "Error moving/deleting entry with UUID {}: {}".format(uuid, ret)

        def do_groupdelete(self, params):
            """groupdelete <uuid>
            Delete group specified by UUID.
            """
            uuid = params
            if (uuid.startswith('"') and uuid.endswith('"')) or \
               (uuid.startswith("'") and uuid.endswith("'")): uuid = uuid[1:-1]
            ret = database_delete_group(kdba[0], uuid)
            if ret == 0:
                self.prompt = "*kpcli> "
                print "Successfully deleted group with UUID {}".format(uuid)
            else:
                print "Error moving/deleting group with UUID {}: {}".format(uuid, ret)

        def do_EOF(self, line):
            return self.do_quit(line)

def randomString(allowedChars, length):
    """Generate random string of given length consisting of chars contained in the allowedChars string."""
    rnd = random.SystemRandom()

    return "".join(rnd.choice(allowedChars) for i in range(length))

def copyToClipboard(text, timeout=12):
    """Function to copy given text to clipboard and wait (timeout seconds, before emptying cliboard out)"""

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

# Print out retrieved data
def map_none(x):
    if x == None: return "None"
    else: return '"{}"'.format(x)

def database_group_dump(kdb):
    """Dump all the groups including their UUIDs"""
    print "UUID\t\t\t\t\tGroup name\tParent group UUID\tNotes"

    for elem in kdb.obj_root.iterfind('.//Group'):
        name = ""
        notes = ""
        cuuid = ""
        puuid = None

        val = elem.find('./Name')
        if val is not None and val.text is not None and val.text != "":
            name = val.text
        val = elem.find('./Notes')
        if val is not None and val.text is not None and val.text != "":
            notes = val.text
        val = elem.find('./UUID')
        if val is not None and val.text is not None and val.text != "":
            try:
                cuuid = str(uuid.UUID(bytes=base64.b64decode(val.text)))
            except Exception as e:
                print "ERROR: Invalid UUID: {}".format(e)

        # Find parent group if it exists and extract it's uuid as well
        pelem = elem.getparent()
        #pelem = elem.find("../../Group")
        if pelem is not None:
            val = pelem.find('./UUID')
            if val is not None and val.text is not None and val.text != "":
                try:
                    puuid = str(uuid.UUID(bytes=base64.b64decode(val.text)))
                except Exception as e:
                    print "ERROR: Invalid UUID: {}".format(e)

        print "{}\t{}\t{}\t{}".format(*map(map_none, [cuuid, name, puuid, notes]))

def database_add_modify_group(kdb, keyVals):
    """Add new or modify existing Group in the XML tree.
    If uuid key is present, Group is modified,
    else if parent_group_uuid is present new group is added inside requested parent_group_uuid.
    If parent_group_uuid is None, then create root group if one does not yet exist."""
    retuuid = None
    keyMap = { 'name': 'Name', 'notes': 'Notes', 'iconid': 'IconID' }

    # Override iconid with '49' if not present
    if 'iconid' not in keyVals:
        keyVals['iconid'] = "49"

    if "uuid" in keyVals:
        retuuid = keyVals['uuid']
        try:
            encuuid = base64.b64encode(uuid.UUID("urn:uuid:{}".format(keyVals['uuid'])).bytes)
        except Exception as e:
            print "ERROR: Invalid UUID: {}".format(e)
            return None

        del keyVals['uuid']
        for elem in kdb.obj_root.iterfind('.//Group'):
            val = elem.find('./UUID')
            if val is not None and val.text is not None and val.text == encuuid:
                for k, v in keyVals.iteritems():
                    km = keyMap[k]
                    # Try to find existing entry
                    elem2 = elem.find("./{}".format(km))
                    if elem2 is not None:
                        elem2._setText(v)
                    else:
                        etree.SubElement(elem, km)._setText(v)
                break
    elif "parent_group_uuid" in keyVals:
        if 'name' not in keyVals:
            print "ERROR: Name missing!"
            return retuuid
        if 'notes' not in keyVals:
            keyVals['notes'] = None
        retuuid = None
        newuuid = None
        encnewuuid = None
        encuuid = None
        try:
            if keyVals['parent_group_uuid'] != 'None':
                encuuid = base64.b64encode(uuid.UUID("urn:uuid:{}".format(keyVals['parent_group_uuid'])).bytes)
            nuuid = uuid.uuid4()
            newuuid = str(nuuid)
            encnewuuid = base64.b64encode(nuuid.bytes)
        except Exception as e:
            print "ERROR: Invalid group UUID: {}".format(e)
            return None

        del keyVals['parent_group_uuid']

        parent = None
        if encuuid is None:
            rootElem = kdb.obj_root.find('.//Root')
            if rootElem is not None:
                if rootElem.find('./Group') is not None:
                    print "ERROR: Unable to add new root group, until old root is deleted!"
                else:
                    parent = rootElem
                    retuuid = newuuid
        else:
            for elem in kdb.obj_root.iterfind('.//Group'):
                val = elem.find('./UUID')
                if val is not None and val.text is not None and val.text == encuuid:
                    parent = elem
                    retuuid = newuuid
                    break

        # Create new Group element
        if parent is not None:
            group = etree.SubElement(parent, "Group")
            etree.SubElement(group, "UUID")._setText(encnewuuid)
            for k, v in keyVals.iteritems():
                km = keyMap[k]
                etree.SubElement(group, km)._setText(v)
            times = etree.SubElement(group, "Times")
            cdt = datetime.datetime.utcnow()
            cdtstr = cdt.strftime("%Y-%m-%dT%H:%M:%SZ")
            etree.SubElement(times, "CreationTime")._setText(cdtstr)
            etree.SubElement(times, "LastModificationTime")._setText(cdtstr)
            etree.SubElement(times, "LastAccessTime")._setText(cdtstr)
            etree.SubElement(times, "ExpiryTime")._setText(cdtstr)
            etree.SubElement(times, "Expires")._setText("False")
            etree.SubElement(times, "UsageCount")._setText("0")
            etree.SubElement(times, "LocationChanged")._setText(cdtstr)
            etree.SubElement(group, "IsExpanded")._setText("True")
            etree.SubElement(group, "DefaultAutoTypeSequence")
            etree.SubElement(group, "EnableAutoType")._setText("null")
            etree.SubElement(group, "EnableSearching")._setText("null")
            etree.SubElement(group, "LastTopVisibleEntry")._setText("AAAAAAAAAAAAAAAAAAAAAA==")
    else:
        print "ERROR: At least uuid or parent_group_uuid keys should be present!"

    return retuuid

def database_add_modify(kdb, keyVals):
    """Add new or modify existing Entry in the XML tree.
    If uuid key is present, entry is modified,
    else if group_uuid is present new entry is added to requested group_uuid."""
    retuuid = None
    keyMap = { 'title': 'Title', 'username': 'UserName', 'password': 'Password', 'url': 'URL', 'notes': 'Notes' }

    if "uuid" in keyVals:
        retuuid = keyVals['uuid']
        try:
            encuuid = base64.b64encode(uuid.UUID("urn:uuid:{}".format(keyVals['uuid'])).bytes)
        except Exception as e:
            print "ERROR: Invalid UUID: {}".format(e)
            return None

        del keyVals['uuid']
        for elem in kdb.obj_root.iterfind('.//Group/Entry'):
            val = elem.find('./UUID')
            if val is not None and val.text is not None and val.text == encuuid:
                for k, v in keyVals.iteritems():
                    km = keyMap[k]
                    found = False
                    # Try to find existing entry
                    elem2 = None
                    for elem2 in elem.iterfind("./String"):
                        key = elem2.find("./Key")
                        val = elem2.find("./Value")
                        if key is None or key.text is None or key.text != km: continue
                        found = True
                        if val == None:
                            val = etree.Element('Value')
                            elem2.append(val)
                        if k == "password" and v == "~":
                            randomPass = randomString(RANDOM_PASS_CHARS, RANDOM_PASS_LENGTH)
                            print "Random password generated: {}".format(randomPass)
                            val._setText(randomPass)
                        else:
                            val._setText(v)
                    # If not found, add new String element
                    if not found:
                        string = etree.Element('String')
                        key = etree.Element('Key')
                        val = etree.Element('Value')
                        key.text = km
                        if k == "password": val.set('Protected', 'False')
                        if k == "password" and v == "~":
                            randomPass = randomString(RANDOM_PASS_CHARS, RANDOM_PASS_LENGTH)
                            print "Random password generated: {}".format(randomPass)
                            val.text = randomPass
                        else:
                            val.text = v
                        string.append(key)
                        string.append(val)
                        if elem2 != None: elem2.addnext(string)
                        else: elem.append(string)
                break
    elif "group_uuid" in keyVals:
        retuuid = None
        newuuid = None
        encnewuuid = None
        try:
            encuuid = base64.b64encode(uuid.UUID("urn:uuid:{}".format(keyVals['group_uuid'])).bytes)
            nuuid = uuid.uuid4()
            newuuid = str(nuuid)
            encnewuuid = base64.b64encode(nuuid.bytes)
        except Exception as e:
            print "ERROR: Invalid group UUID: {}".format(e)
            return None

        del keyVals['group_uuid']
        for elem in kdb.obj_root.iterfind('.//Group'):
            val = elem.find('./UUID')
            if val is not None and val.text is not None and val.text == encuuid:
                # Create new Entry under this Group node
                entry = etree.SubElement(elem, "Entry")
                etree.SubElement(entry, "UUID")._setText(encnewuuid)
                etree.SubElement(entry, "IconID")._setText("0")
                etree.SubElement(entry, "ForegroundColor")
                etree.SubElement(entry, "BackgroundColor")
                etree.SubElement(entry, "OverrideURL")
                etree.SubElement(entry, "Tags")
                times = etree.SubElement(entry, "Times")
                cdt = datetime.datetime.utcnow()
                cdtstr = cdt.strftime("%Y-%m-%dT%H:%M:%SZ")
                etree.SubElement(times, "CreationTime")._setText(cdtstr)
                etree.SubElement(times, "LastModificationTime")._setText(cdtstr)
                etree.SubElement(times, "LastAccessTime")._setText(cdtstr)
                etree.SubElement(times, "ExpiryTime")._setText(cdtstr)
                etree.SubElement(times, "Expires")._setText("False")
                etree.SubElement(times, "UsageCount")._setText("0")
                etree.SubElement(times, "LocationChanged")._setText(cdtstr)
                for k, v in keyVals.iteritems():
                    km = keyMap[k]
                    string = etree.SubElement(entry, "String")
                    etree.SubElement(string, "Key")._setText(km)
                    val = etree.SubElement(string, "Value")
                    if k == "password" and v == "~":
                        randomPass = randomString(RANDOM_PASS_CHARS, RANDOM_PASS_LENGTH)
                        print "Random password generated: {}".format(randomPass)
                        val._setText(randomPass)
                    else:
                        val._setText(v)
                autoType = etree.SubElement(entry, "AutoType")
                etree.SubElement(autoType, "Enabled")._setText("True")
                etree.SubElement(autoType, "DataTransferObfuscation")._setText("0")
                association = etree.SubElement(autoType, "Association")
                etree.SubElement(association, "Window")._setText("Target Window")
                etree.SubElement(association, "KeystrokeSequence")._setText("{USERNAME}{TAB}{PASSWORD}{TAB}{ENTER}")

                retuuid = newuuid
                break
    else:
        print "ERROR: At least uuid or group_uuid keys should be present!"

    return retuuid

def database_delete(kdb, uuId):
    """Delete given entry by uuid"""
    try:
        encuuid = base64.b64encode(uuid.UUID("urn:uuid:{}".format(uuId)).bytes)
    except Exception as e:
        print "ERROR: Invalid UUID: {}".format(e)
        return 1

    ret = 2
    for elem in kdb.obj_root.iterfind('.//Group/Entry'):
        val = elem.find('./UUID')
        if val is not None and val.text is not None and val.text == encuuid:
            parent = elem.getparent()
            if parent is not None:
                parent.remove(elem)
            ret = 0
            break

    return ret

def database_delete_group(kdb, uuId):
    """Delete given group by uuid"""
    try:
        encuuid = base64.b64encode(uuid.UUID("urn:uuid:{}".format(uuId)).bytes)
    except Exception as e:
        print "ERROR: Invalid UUID: {}".format(e)
        return 1

    ret = 2
    for elem in kdb.obj_root.iterfind('.//Group'):
        val = elem.find('./UUID')
        if val is not None and val.text is not None and val.text == encuuid:
            parent = elem.getparent()
            if parent is not None:
                parent.remove(elem)
            ret = 0
            break

    return ret

def database_dump(kdb, showPasswords = False, filter = None, doCopyToClipboard = None, copyToClipboardTimeout = None):
    """Dump the database, optionally limiting output by regexps by fields (filter).

    If showPasswords is true also show passwords in the output.
    If doCopyToClipboard is not None, copy requested field name to clipboard.
    If copyToClipboardTimeout is not None, use it as override timer for copy to clipboard function."""

    print "UUID\tTitle\tUsername\tPassword\tURL\tNotes\tGroup Name\tGroup UUID"
    isfirst = True
    for elem in kdb.obj_root.iterfind('.//Group/Entry'):
        title = ""
        username = ""
        password = ""
        url = ""
        notes = ""
        cuuid = ""
        groupName = ""
        groupUuid = ""

        val = elem.find('./UUID')
        if val is not None and val.text is not None and val.text != "":
            try:
                cuuid = str(uuid.UUID(bytes=base64.b64decode(val.text)))
            except Exception as e:
                print "ERROR: Invalid UUID: {}".format(e)
        for sel in elem.iterfind('./String'):
            key = sel.find('./Key')
            val = sel.find('./Value')
            if key is None or val is None: continue

            if "Title" == key.text: title = val.text
            elif "UserName" == key.text: username = val.text
            elif "Password" == key.text:
                origPassword = password = val.text
                if not showPasswords: password = "".join(map(lambda x: "*", password))
            elif "URL" == key.text: url = val.text
            elif "Notes" == key.text: notes = val.text

        # Try to retrieve group name as well
        group = elem.getparent()
        if group is not None:
            val = group.find('./Name')
            if val is not None and val.text is not None and val.text != "":
                groupName = val.text
            val = group.find('./UUID')
            if val is not None and val.text is not None and val.text != "":
                try:
                    groupUuid = str(uuid.UUID(bytes=base64.b64decode(val.text)))
                except Exception as e:
                    print "ERROR: Invalid group UUID: {}".format(e)

        # Check if filter allows showing data
        if filter != None:
            if filter.has_key("uuid"):
                if (cuuid == None and filter["uuid"] != None) or \
                   (cuuid != None and filter["uuid"] == None) or \
                   (cuuid != None and filter["uuid"] != None and filter["uuid"].search(cuuid) == None): continue
            if filter.has_key("title"):
                if (title == None and filter["title"] != None) or \
                   (title != None and filter["title"] == None) or \
                   (title != None and filter["title"] != None and filter["title"].search(title) == None): continue
            if filter.has_key("username"):
                if (username == None and filter["username"] != None) or \
                   (username != None and filter["username"] == None) or \
                   (username != None and filter["username"] != None and filter["username"].search(username) == None): continue
            if filter.has_key("url"):
                if (url == None and filter["url"] != None) or \
                   (url != None and filter["url"] == None) or \
                   (url != None and filter["url"] != None and filter["url"].search(url) == None): continue
            if filter.has_key("groupname"):
                if (groupName == None and filter["groupname"] != None) or \
                   (groupName != None and filter["groupname"] == None) or \
                   (groupName != None and filter["groupname"] != None and filter["groupname"].search(groupName) == None): continue
            if filter.has_key("groupuuid"):
                if (groupUuid == None and filter["groupuuid"] != None) or \
                   (groupUuid != None and filter["groupuuid"] == None) or \
                   (groupUuid != None and filter["groupuuid"] != None and filter["groupuuid"].search(groupUuid) == None): continue

        print "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}".format(*map(map_none, [cuuid, title, username, password, url, notes, groupName, groupUuid]))

        if isfirst and doCopyToClipboard != None:
            copyText = None
            if doCopyToClipboard == "password":
                copyText = origPassword
            elif doCopyToClipboard == "username":
                copyText = username
            elif doCopyToClipboard == "url":
                copyText = url

            if copyText != None:
                if copyToClipboardTimeout != None: copyToClipboard(copyText, copyToClipboardTimeout)
                else: copyToClipboard(copyText)
        isfirst = False

def decode_input_value_and_regex(value):
    """Decodes input unquotes or quoted value and if not None, return regex of it.

    Decode value using the following rules:
    If value == None or value == "None" then return None
    If len(value) > 2 and ((value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'"))): return value[1:-1]"""

    if value == None or value == "None": return None
    if len(value) > 2 and ((value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'"))): return re.compile(value[1:-1], re.I)

    return re.compile(value, re.I)

# Parse command line options
parser = argparse.ArgumentParser()
parser.add_argument('-v', '--version', action='version', version=VERSION_STR)
parser.add_argument('-f', '--file', dest='file', nargs='?', default='test.kdbx', help='KDB4 file (.kdbx)')
parser.add_argument('-k', '--keyfile', dest='keyfile', nargs='?', help='Additional keyfile to use as master key')
parser.add_argument('-p', '--password', dest='password', action='store_const', const=True, default=False, help='Shall we show password (if this argument is not given, asterisks are shown instead of password)')
parser.add_argument('-t', '--title', dest='title', nargs='?', help='Optional regex value to filter only required titles')
parser.add_argument('-u', '--username', dest='username', nargs='?', help='Optional regex value to filter only required usernames')
parser.add_argument('--uuid', dest='uuid', nargs='?', help='Optional UUID regex value to filter only entries with matching UUID')
parser.add_argument('--url', dest='url', nargs='?', help='Optional URL regex value to filter only entries with matching URL')
parser.add_argument('--groupname', dest='groupname', nargs='?', help='Optional URL regex value to filter only entries with matching group names')
parser.add_argument('--groupuuid', dest='groupuuid', nargs='?', help='Optional URL regex value to filter only entries with matching group uuid')
parser.add_argument('-c', '--copy', dest='copy', nargs='?', help='Optional requirement to copy specified field (password, username or url) to clipboard (if this function is supported for your OS)')
parser.add_argument('--pprint', dest='dopprint', action='store_const', const=True, default=False, help='Optional requirement to first pretty print database out')
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
    if args.uuid != None: print "Show only UUID entries matching regexp '{}'".format(args.uuid)
    if args.url != None: print "Show only URL entries matching regexp '{}'".format(args.url)
    if args.groupname != None: print "Show only entries in the group name matching regexp '{}'".format(args.groupname)
    if args.groupuuid != None: print "Show only entries in the group uuid matching regexp '{}'".format(args.groupuuid)
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
    stream.close()
    stream = None
    kdb = kdba[0]

    if isinstance(kdb, kp.kdb3.KDB3Reader):
        raise Exception("KDB3 (.kdb, KeePass 1.x) database format not supported!")
    elif isinstance(kdb, kp.kdb4.KDB4Reader):
        pass
    else:
        raise Exception("Unknown/unsupported database format implementation in libkeepass!")

    if args.dopprint: print kdb.pretty_print()
    if interactive:
        options = { 'show_passwords_bool': showPasswords, 'copy_to_clipboard_str': args.copy }
        Shell(kdba, args.file, masterPassword, args.keyfile, options).cmdloop()
    else:
        filters = {}
        if args.title != None: filters['title'] = decode_input_value_and_regex(args.title)
        if args.username != None: filters['username'] = decode_input_value_and_regex(args.username)
        if args.uuid != None: filters['uuid'] = decode_input_value_and_regex(args.uuid)
        if args.url != None: filters['url'] = decode_input_value_and_regex(args.url)
        if args.groupname != None: filters['groupname'] = decode_input_value_and_regex(args.groupname)
        if args.groupuuid != None: filters['groupuuid'] = decode_input_value_and_regex(args.groupuuid)
        database_dump(kdb, showPasswords, filters, args.copy)
except Exception as e:
    print "ERROR: {}".format(e)
    if DEBUG:
        traceback.print_exc(file=sys.stdout)
finally:
    if kdba[0] != None: kdba[0].close()
    if stream != None: stream.close()
