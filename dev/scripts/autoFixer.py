#! /usr/bin/env python

"Process python files to improve python 3 migration"

from __future__ import print_function
import os
import sys
import getopt
# Modified glob version to support **
import glob2
import re

def main():
    tabsize = 8
    try:
        opts, args = getopt.getopt(sys.argv[1:], "t:")
        if not args:
            raise getopt.error, "At least one file argument required"
    except getopt.error as msg:
        print(msg)
        print("usage:", sys.argv[0], "files ...")
        return

    files = []
    for arg in args:
        files.extend(glob2.glob(arg))
    
    for filename in files:
        if "autoFixer" in filename or "build" in filename:
            continue
        process(filename, tabsize)

# Utils, regexes
r1_ = r'([( ,=])(?<![b])\"(([^\n\\\"]|\\.)*(\\x|\\0)([^\n\\\"]|\\.)*)\"'
r2_ = r"([( ,=])(?<![b])\'(([^\n\\\']|\\.)*(\\x|\\0)([^\n\\\']|\\.)*)\'"
#r3_ = r"(?<![\"'\\])(['\"])\1([^\"'])"

r1_r = r'\g<1>b"\2"'
r2_r = r"\g<1>b'\2'"
#r3_r = r"b\1\1\2"

def process(filename, tabsize):
    try:
        f = open(filename)
        text = f.read()
        f.close()
    except IOError as msg:
        print("%r: I/O error: %s" % (filename, msg))
        return
    # Remove tabs
    newtext = text.expandtabs(tabsize)
    # Auto-detect bytes with "\x...", "\0..."
    newtext = re.sub(r1_, r1_r, newtext)
    # Auto-detect bytes with '\x...', '\0...'
    newtext = re.sub(r2_, r2_r, newtext)
    # Auto-detect bytes with '', "" but not """, '''
    #newtext = re.sub(r3_, r3_r, newtext)
    if newtext == text:
        return
    f = open(filename, "w")
    f.write(newtext)
    f.close()
    print(filename)

if __name__ == '__main__':
    main()
