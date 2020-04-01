#!/usr/bin/env python3
# coding: utf-8
#
# This is CLI version of keepasspy. This is just a wrapper for kpcli-impl.py
# to ensure correct Python version.
# Written by Uros Juvan <asmpro@gmail.com> 2014.
# 

import sys

# Check if we have required Python version
if sys.hexversion < 0x03000000:
    sys.exit("Python 3.0 is required!")

from kpcli_impl import *
