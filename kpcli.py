#!/usr/bin/env python
# coding: utf-8
#
# This is CLI version of keepasspy. This is just a wrapper for kpcli-impl.py
# to ensure correct Python version.
# Written by Uros Juvan <asmpro@gmail.com> 2014.
# 

import sys

# Check if we have required Python version
if sys.hexversion < 0x02070000:
    sys.exit("Python 2.7 is required!")

from kpcli_impl import *
