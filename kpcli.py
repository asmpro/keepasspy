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

# This is temporary development hack.
# Later on libkeepass (including all it's requirements should be installed
#                      in the system, so simple import libkeepass should suffice)
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "libkeepass"))

import libkeepass as kp

# Program version
VERSION="1.0"
DEBUG=1

# Parse command line options
parser = argparse.ArgumentParser()
parser.add_argument('-v', '--version', action='version', version='%(prog)s V{}'.format(VERSION))
parser.add_argument('-f', '--file', dest='file', nargs='?', default='test.kdbx', help='KDB4 file (.kdbx)')
parser.add_argument('-k', '--keyfile', dest='keyfile', nargs='?', help='Additional keyfile to use as master key')
args = parser.parse_args()

if DEBUG:
	#from pprint import pprint
	#pprint(args)
	print "File={}".format(args.file)
	if args.keyfile != None: print "Keyfile={}".format(args.keyfile)

masterPassword = getpass.getpass("Master password: ")
if DEBUG:
	print "Master password={}".format(masterPassword)

try :
	with kp.open(args.file, password=masterPassword, keyfile=args.keyfile) as kdb:
		print kdb.pretty_print()
except Exception as e:
	print "ERROR: {}".format(e)
