# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>

"""
Unit testing infrastructure for Scapy
"""

from __future__ import print_function

import bz2
import copy
import code
import getopt
import glob
import hashlib
import importlib
import json
import logging
import os
import os.path
import sys
import threading
import time
import traceback
import warnings
import zlib

from scapy.consts import WINDOWS, DARWIN
import scapy.libs.six as six
from scapy.config import conf
from scapy.compat import base64_bytes, bytes_hex, plain_str
from scapy.themes import DefaultTheme, BlackAndWhite
from scapy.utils import tex_escape


# Check UTF-8 support #

def _utf8_support():
    """
    Check UTF-8 support for the output
    """
    try:
        if six.PY2:
            return False
        if WINDOWS:
            return (sys.stdout.encoding == "utf-8")
        return True
    except AttributeError:
        return False


if _utf8_support():
    arrow = "\u2514"
    dash = "\u2501"
    checkmark = "\u2713"
else:
    arrow = "->"
    dash = "--"
    checkmark = "OK"


#   Util class   #

class Bunch:
    __init__ = lambda self, **kw: setattr(self, '__dict__', kw)


def retry_test(func):
    """Retries the passed function 3 times before failing"""
    success = False
    for _ in range(3):
        try:
            result = func()
        except Exception:
            t, v, tb = sys.exc_info()
            time.sleep(1)
        else:
            success = True
            break
    if not success:
        six.reraise(t, v, tb)
    assert success
    return result


def scapy_path(fname):
    """Resolves a path relative to scapy's root folder"""
    if fname.startswith('/'):
        fname = fname[1:]
    return os.path.abspath(os.path.join(
        os.path.dirname(__file__), '../../', fname
    ))


class no_debug_dissector:
    """Context object used to disable conf.debug_dissector"""
    def __enter__(self):
        self.old_dbg = conf.debug_dissector
        conf.debug_dissector = False

    def __exit__(self, exc_type, exc_value, traceback):
        conf.debug_dissector = self.old_dbg


#    Import tool    #


def import_module(name):
    if name.endswith(".py"):
        name = name[:-3]
    try:
        return importlib.import_module(name, package="scapy")
    except Exception:
        return importlib.import_module(name)


#    INTERNAL/EXTERNAL FILE EMBEDDING    #

class File:
    def __init__(self, name, URL, local):
        self.name = name
        self.local = local.encode("utf8")
        self.URL = URL

    def get_local(self):
        return bz2.decompress(base64_bytes(self.local))

    def get_URL(self):
        return self.URL

    def write(self, dir):
        if dir:
            dir += "/"
        with open(dir + self.name, "wb") as fdesc:
            fdesc.write(self.get_local())


# Embed a base64 encoded bziped version of js and css files
# to work if you can't reach Internet.
class External_Files:
    UTscapy_js = File("UTscapy.js", "https://scapy.net/files/UTscapy/UTscapy.js",  # noqa: E501
                      """QlpoOTFBWSZTWWVijKQAAXxfgERUYOvAChIhBAC
/79+qQAH8AFA0poANAMjQAAAGABo0NGEZNBo0\n0BhgAaNDRhGTQaNNAYFURJinp
lGaKbRkJiekzSenqmpA0Gm1LFMpRUklVQlK9WUTZYpNFI1IiEWE\nFT09Sfj5uO+
qO6S5DQwKIxM92+Zku94wL6V/1KTKan2c66Ug6SmVKy1ZIrgauxMVLF5xLH0lJRQ
u\nKlqLF10iatlTzqvw7S9eS3+h4lu3GZyMgoOude3NJ1pQy8eo+X96IYZw+yneh
siPj73m0rnvQ3QX\nZ9BJQiZQYQ5/uNcl2WOlC5vyQqV/BWsnr2NZYLYXQLDs/Bf
fk4ZfR4/SH6GfA5Xlek4xHNHqbSsR\nbREOgueXo3kcYi94K6hSO3ldD2O/qJXOF
qJ8o3TE2aQahxtQpCVUKQMvODHwu2YkaORYZC6gihEa\nllcHDIAtRPScBACAJnU
ggYhLDX6DEko7nC9GvAw5OcEkiyDUbLdiGCzDaXWMC2DuQ2Y6sGf6NcRu\nON7QS
bhHsPc4KKmZ/xdyRThQkGVijKQ=\n""")
    UTscapy_css = File("UTscapy.css", "https://scapy.net/files/UTscapy/UTscapy.css",  # noqa: E501
                       """QlpoOTFBWSZTWbpATIwAAFpfgHwQSB//+Cpj2Q
C//9/6UAS5t7qcLut3NNDp0gxKMmpqaep6n6iP\n1J+pPU0yAAaeoaDI0BJCTJqa
j1BoaGhoAAPSAAAJNSRqmmk8TQmj1DT1Hom1HkQABoNDmmJgATAB\nMAAJgACYJI
hDQUzCR5Q0niRoaAGgGmZS+faw7LNbkliDG1Q52WJCd85cxRVVKegld8qCRISoto
GD\nEGREFEYRW0CxAgTb13lodjuN7E1aCFgRFVhiEmZAZ/ek+XR0c8DWiAKpBgY2
LNpQ1rOvlnoUI1Al\n0ySaP1w2MyFxoQqRicScCm6WnQOxDnufxk8s2deLLKlN+r
fvxyTTCGRAWZONkVGIxVQRZGZLeAwH\nbpQXZcYj467i85knEOYWmLcokaqEGYGS
xMCpD+cOIaL7GCxEU/aNSlWFNCvQBvzb915huAgdIdD2\nya9ZQGoqrmtommfAxu
7FGTDBNBfir9UkAMmT1KRzxasJ0n2OE+mlgTZzJnhydbJaMtAk8DJzUuvv\nZpc3
CJLVyr8F3NmIQO5E3SJSY3SQnk1CQwlELqFutXjeWWzmiywo7xJk5rUcVOV9+Ro4
96WmXsUr\nkKhNocbnFztqPhesccW5kja+KuNFmzdw4DVOBJ2JPhGOYSwCUiwUe2
kOshYBdULUmwYwToAGdgA9\n5n3bSpG85LUFIE0Cw78EYVgY0ESnYW5UdfgBhj1w
PiiXDEG2vAtr38O9kdwg3tFU/0okilEjDYDa\nEfkomkLUSokmE8g1fMYBqQyyaP
RWmySO3EtAuMVhQqIuMldOzLqWubl7k1MnhuBaELOgtB2TChcS\n0k7jvgdBKIef
UkdAf3t2GO/LVSrDvkcb4l4TrwrI7JeCo8pBvXqZBqZJSqbsAziG7QDQVNqdtFGz
\nEvMKOvKvUQ6mJFigLxBnziGQGQDEMQPSGhlV2BwAN6rZEmLwgED0OrEiSxXDcB
MDskp36AV7IbKa\nCila/Wm1BKhBF+ZIqtiFyYpUhI1Q5+JK0zK7aVyLS9y7GaSr
NCRpr7uaa1UgapVKs6wKKQzYCWsV\n8iCGrAkgWZEnDMJWCGUZOIpcmMle1UXSAl
d5OoUYXNo0L7WSOcxEkSGjCcRhjvMRP1pAUuBPRCRA\n2lhC0ZgLYDAf5V2agMUa
ki1ZgOQDXQ7aIDTdjGRTgnzPML0V1X+tIoSSZmZhrxZbluMWGEkwwky6\n0ObWIM
cEbX4cawPPBVc6m5UUPbEmBANyjtNvTKE2ri7oOmBVKIMLqQKm+4rlmisu2uGSxW
zTov5w\nqQDp61FkHk40wzQUKk4YcBlbQT1l8VXeZJYAVFjSJIcC8JykBYZJ1yka
I4LDm5WP7s2NaRkhhV7A\nFVSD5zA8V/DJzfTk0QHmCT2wRgwPKjP60EqqlDUaST
/i7kinChIXSAmRgA==\n""")

    def get_local_dict(cls):
        return {x: y.name for (x, y) in six.iteritems(cls.__dict__)
                if isinstance(y, File)}
    get_local_dict = classmethod(get_local_dict)

    def get_URL_dict(cls):
        return {x: y.URL for (x, y) in six.iteritems(cls.__dict__)
                if isinstance(y, File)}
    get_URL_dict = classmethod(get_URL_dict)


#    HELPER CLASSES FOR PARAMETRING OUTPUT FORMAT    #

class EnumClass:
    def from_string(cls, x):
        return cls.__dict__[x.upper()]
    from_string = classmethod(from_string)


class Format(EnumClass):
    TEXT = 1
    ANSI = 2
    HTML = 3
    LATEX = 4
    XUNIT = 5
    LIVE = 6


#    TEST CLASSES    #

class TestClass:
    def __getitem__(self, item):
        return getattr(self, item)

    def add_keywords(self, kws):
        if isinstance(kws, six.string_types):
            kws = [kws.lower()]
        for kwd in kws:
            kwd = kwd.lower()
            if kwd.startswith('-'):
                try:
                    self.keywords.remove(kwd[1:])
                except KeyError:
                    pass
            else:
                self.keywords.add(kwd)


class TestCampaign(TestClass):
    def __init__(self, title):
        self.title = title
        self.filename = None
        self.headcomments = ""
        self.campaign = []
        self.keywords = set()
        self.crc = None
        self.sha = None
        self.preexec = None
        self.preexec_output = None
        self.end_pos = 0
        self.interrupted = False
        self.duration = 0.0

    def add_testset(self, testset):
        self.campaign.append(testset)
        testset.keywords.update(self.keywords)

    def trunc(self, index):
        self.campaign = self.campaign[:index]

    def startNum(self, beginpos):
        for ts in self:
            for t in ts:
                t.num = beginpos
                beginpos += 1
        self.end_pos = beginpos

    def __iter__(self):
        return self.campaign.__iter__()

    def all_tests(self):
        for ts in self:
            for t in ts:
                yield t


class TestSet(TestClass):
    def __init__(self, name):
        self.name = name
        self.tests = []
        self.comments = ""
        self.keywords = set()
        self.crc = None
        self.expand = 1

    def add_test(self, test):
        self.tests.append(test)
        test.keywords.update(self.keywords)

    def trunc(self, index):
        self.tests = self.tests[:index]

    def __iter__(self):
        return self.tests.__iter__()


class UnitTest(TestClass):
    def __init__(self, name):
        self.name = name
        self.test = ""
        self.comments = ""
        self.result = "passed"
        self.fresult = ""
        # make instance True at init to have a different truth value than None
        self.duration = 0
        self.output = ""
        self.num = -1
        self.keywords = set()
        self.crc = None
        self.expand = 1

    def prepare(self, theme):
        if six.PY2:
            self.test = self.test.decode("utf8", "ignore")
            self.output = self.output.decode("utf8", "ignore")
            self.comments = self.comments.decode("utf8", "ignore")
            self.result = self.result.decode("utf8", "ignore")
        if self.result == "passed":
            self.fresult = theme.success(self.result)
        else:
            self.fresult = theme.fail(self.result)

    def __nonzero__(self):
        return self.result == "passed"
    __bool__ = __nonzero__


# Careful note: all data not included will be set by default.
# Use -c as first argument !!
def parse_config_file(config_path, verb=3):
    """Parse provided json to get configuration
    Empty default json:
    {
      "testfiles": [],
      "breakfailed": true,
      "onlyfailed": false,
      "verb": 3,
      "dump": 0,
      "docs": 0,
      "crc": true,
      "preexec": {},
      "global_preexec": "",
      "outputfile": null,
      "local": true,
      "format": "ansi",
      "num": null,
      "modules": [],
      "kw_ok": [],
      "kw_ko": []
    }

    """
    with open(config_path) as config_file:
        data = json.load(config_file)
        if verb > 2:
            print(" %s Loaded config file" % arrow, config_path)

    def get_if_exist(key, default):
        return data[key] if key in data else default
    return Bunch(testfiles=get_if_exist("testfiles", []),
                 breakfailed=get_if_exist("breakfailed", True),
                 remove_testfiles=get_if_exist("remove_testfiles", []),
                 onlyfailed=get_if_exist("onlyfailed", False),
                 verb=get_if_exist("verb", 3),
                 dump=get_if_exist("dump", 0), crc=get_if_exist("crc", 1),
                 docs=get_if_exist("docs", 0),
                 preexec=get_if_exist("preexec", {}),
                 global_preexec=get_if_exist("global_preexec", ""),
                 outfile=get_if_exist("outputfile", sys.stdout),
                 local=get_if_exist("local", False),
                 num=get_if_exist("num", None),
                 modules=get_if_exist("modules", []),
                 kw_ok=get_if_exist("kw_ok", []),
                 kw_ko=get_if_exist("kw_ko", []),
                 format=get_if_exist("format", "ansi"))

#    PARSE CAMPAIGN    #


def parse_campaign_file(campaign_file):
    test_campaign = TestCampaign("Test campaign")
    test_campaign.filename = campaign_file.name
    testset = None
    test = None
    testnb = 0

    for line in campaign_file.readlines():
        if line[0] == '#':
            continue
        if line[0] == "~":
            (test or testset or test_campaign).add_keywords(line[1:].split())
        elif line[0] == "%":
            test_campaign.title = line[1:].strip()
        elif line[0] == "+":
            testset = TestSet(line[1:].strip())
            test_campaign.add_testset(testset)
            test = None
        elif line[0] == "=":
            test = UnitTest(line[1:].strip())
            test.num = testnb
            testnb += 1
            if testset is None:
                error_m = "Please create a test set (i.e. '+' section)."
                raise getopt.GetoptError(error_m)
            testset.add_test(test)
        elif line[0] == "*":
            if test is not None:
                test.comments += line[1:]
            elif testset is not None:
                testset.comments += line[1:]
            else:
                test_campaign.headcomments += line[1:]
        else:
            if test is None:
                if line.strip():
                    raise ValueError("Unknown content [%s]" % line.strip())
            else:
                test.test += line
    return test_campaign


def dump_campaign(test_campaign):
    print("#" * (len(test_campaign.title) + 6))
    print("## %(title)s ##" % test_campaign)
    print("#" * (len(test_campaign.title) + 6))
    if test_campaign.sha and test_campaign.crc:
        print("CRC=[%(crc)s] SHA=[%(sha)s]" % test_campaign)
    print("from file %(filename)s" % test_campaign)
    print()
    for ts in test_campaign:
        if ts.crc:
            print("+--[%s]%s(%s)--" % (ts.name, "-" * max(2, 80 - len(ts.name) - 18), ts.crc))  # noqa: E501
        else:
            print("+--[%s]%s" % (ts.name, "-" * max(2, 80 - len(ts.name) - 6)))
        if ts.keywords:
            print("  kw=%s" % ",".join(ts.keywords))
        for t in ts:
            print("%(num)03i %(name)s" % t)
            c = k = ""
            if t.keywords:
                k = "kw=%s" % ",".join(t.keywords)
            if t.crc:
                c = "[%(crc)s] " % t
            if c or k:
                print("    %s%s" % (c, k))


def docs_campaign(test_campaign):
    print("%(title)s" % test_campaign)
    print("=" * (len(test_campaign.title)))
    print()
    if len(test_campaign.headcomments):
        print("%s" % test_campaign.headcomments.strip().replace("\n", ""))
        print()
    for ts in test_campaign:
        print("%s" % ts.name)
        print("-" * len(ts.name))
        print()
        if len(ts.comments):
            print("%s" % ts.comments.strip().replace("\n", ""))
            print()
        for t in ts:
            print("%s" % t.name)
            print("^" * len(t.name))
            print()
            if len(t.comments):
                print("%s" % t.comments.strip().replace("\n", ""))
                print()
            print("Usage example::")
            for line in t.test.split('\n'):
                if not line.rstrip().endswith('# no_docs'):
                    print("\t%s" % line)


#    COMPUTE CAMPAIGN DIGESTS    #
if six.PY2:
    def crc32(x):
        return "%08X" % (0xffffffff & zlib.crc32(x))

    def sha1(x):
        return hashlib.sha1(x).hexdigest().upper()
else:
    def crc32(x):
        return "%08X" % (0xffffffff & zlib.crc32(bytearray(x, "utf8")))

    def sha1(x):
        return hashlib.sha1(x.encode("utf8")).hexdigest().upper()


def compute_campaign_digests(test_campaign):
    dc = ""
    for ts in test_campaign:
        dts = ""
        for t in ts:
            dt = t.test.strip()
            t.crc = crc32(dt)
            dts += "\0" + dt
        ts.crc = crc32(dts)
        dc += "\0\x01" + dts
    test_campaign.crc = crc32(dc)
    with open(test_campaign.filename) as fdesc:
        test_campaign.sha = sha1(fdesc.read())


#    FILTER CAMPAIGN     #

def filter_tests_on_numbers(test_campaign, num):
    if num:
        for ts in test_campaign:
            ts.tests = [t for t in ts.tests if t.num in num]
        test_campaign.campaign = [ts for ts in test_campaign.campaign
                                  if ts.tests]


def _filter_tests_kw(test_campaign, kw, keep):
    def kw_match(lst, kw):
        return any(k for k in lst if kw == k)

    if kw:
        kw = kw.lower()
        if keep:
            cond = lambda x: x
        else:
            cond = lambda x: not x
        for ts in test_campaign:
            ts.tests = [t for t in ts.tests if cond(kw_match(t.keywords, kw))]


def filter_tests_keep_on_keywords(test_campaign, kw):
    return _filter_tests_kw(test_campaign, kw, True)


def filter_tests_remove_on_keywords(test_campaign, kw):
    return _filter_tests_kw(test_campaign, kw, False)


def remove_empty_testsets(test_campaign):
    test_campaign.campaign = [ts for ts in test_campaign.campaign if ts.tests]


# RUN TEST #

def _run_test_timeout(test, get_interactive_session, verb=3, my_globals=None):
    """Run a test with timeout"""
    from scapy.autorun import StopAutorunTimeout
    try:
        return get_interactive_session(test,
                                       timeout=5 * 60,  # 5 min
                                       verb=verb,
                                       my_globals=my_globals)
    except StopAutorunTimeout:
        return "-- Test timed out ! --", False


def run_test(test, get_interactive_session, theme, verb=3,
             my_globals=None):
    """An internal UTScapy function to run a single test"""
    start_time = time.time()
    test.output, res = _run_test_timeout(test.test.strip(), get_interactive_session, verb=verb, my_globals=my_globals)
    test.result = "failed"
    try:
        if res is None or res:
            test.result = "passed"
        if test.output.endswith('KeyboardInterrupt\n'):
            test.result = "interrupted"
            raise KeyboardInterrupt
    except Exception:
        test.output += "UTscapy: Error during result interpretation:\n"
        test.output += "".join(traceback.format_exception(sys.exc_info()[0], sys.exc_info()[1], sys.exc_info()[2],))
    finally:
        test.duration = time.time() - start_time
        if test.result == "failed":
            from scapy.sendrecv import debug
            # Add optional debugging data to log
            if debug.crashed_on:
                cls, val = debug.crashed_on
                test.output += "\n\nPACKET DISSECTION FAILED ON:\n %s(hex_bytes('%s'))" % (cls.__name__, plain_str(bytes_hex(val)))
                debug.crashed_on = None
        test.prepare(theme)
        if verb > 2:
            print("%(fresult)6s %(crc)s %(duration)06.2fs %(name)s" % test)
        elif verb > 1:
            print("%(fresult)6s %(crc)s %(name)s" % test)

    return bool(test)

# RUN CAMPAIGN #


def import_UTscapy_tools(ses):
    """Adds UTScapy tools directly to a session"""
    ses["Bunch"] = Bunch
    ses["retry_test"] = retry_test
    ses["scapy_path"] = scapy_path
    ses["no_debug_dissector"] = no_debug_dissector
    if WINDOWS:
        from scapy.arch.windows import _route_add_loopback
        _route_add_loopback()
        ses["conf"].ifaces = conf.ifaces
        ses["conf"].route.routes = conf.route.routes
        ses["conf"].route6.routes = conf.route6.routes


def run_campaign(test_campaign, get_interactive_session, theme,
                 drop_to_interpreter=False, verb=3,
                 scapy_ses=None):
    passed = failed = 0
    if test_campaign.preexec:
        test_campaign.preexec_output = get_interactive_session(
            test_campaign.preexec.strip(),
            my_globals=scapy_ses
        )[0]

    # Drop
    def drop(scapy_ses):
        code.interact(banner="Test '%s' failed. "
                             "exit() to stop, Ctrl-D to leave "
                             "this interpreter and continue "
                             "with the current test campaign"
                             % t.name, local=scapy_ses)

    try:
        for i, testset in enumerate(test_campaign):
            for j, t in enumerate(testset):
                if run_test(t, get_interactive_session, theme,
                            verb=verb, my_globals=scapy_ses):
                    passed += 1
                else:
                    failed += 1
                    if drop_to_interpreter:
                        drop(scapy_ses)
                test_campaign.duration += t.duration
    except KeyboardInterrupt:
        failed += 1
        testset.trunc(j + 1)
        test_campaign.trunc(i + 1)
        test_campaign.interrupted = True
        if verb:
            print("Campaign interrupted!")
            if drop_to_interpreter:
                drop(scapy_ses)

    test_campaign.passed = passed
    test_campaign.failed = failed
    style = [theme.success, theme.fail][bool(failed)]
    if verb > 2:
        print("Campaign CRC=%(crc)s in %(duration)06.2fs SHA=%(sha)s" % test_campaign)
        print(style("PASSED=%i FAILED=%i" % (passed, failed)))
    elif verb:
        print("Campaign CRC=%(crc)s  SHA=%(sha)s" % test_campaign)
        print(style("PASSED=%i FAILED=%i" % (passed, failed)))
    return failed


#    INFO LINES    #

def info_line(test_campaign, theme):
    filename = test_campaign.filename
    duration = test_campaign.duration
    if duration > 10:
        duration = theme.format(duration, "bg_red+white")
    elif duration > 5:
        duration = theme.format(duration, "red")
    if filename is None:
        return "Run at %s by UTscapy in %s" % (
            time.strftime("%H:%M:%S"),
            duration
        )
    else:
        return "Run at %s from [%s] by UTscapy in %s" % (
            time.strftime("%H:%M:%S"),
            filename,
            duration
        )


def html_info_line(test_campaign):
    filename = test_campaign.filename
    if filename is None:
        return """Run %s by <a href="http://www.secdev.org/projects/UTscapy/">UTscapy</a><br>""" % time.ctime()  # noqa: E501
    else:
        return """Run %s from [%s] by <a href="http://www.secdev.org/projects/UTscapy/">UTscapy</a><br>""" % (time.ctime(), filename)  # noqa: E501


def latex_info_line(test_campaign):
    filename = test_campaign.filename
    if filename is None:
        return """by UTscapy""", """%s""" % time.ctime()
    else:
        return """from %s by UTscapy""" % tex_escape(filename), """%s""" % time.ctime()


#    CAMPAIGN TO something    #

def campaign_to_TEXT(test_campaign, theme):
    ptheme = [lambda x: x, theme.success][bool(test_campaign.passed)]
    ftheme = [lambda x: x, theme.fail][bool(test_campaign.failed)]

    output = theme.green("\n%(title)s\n" % test_campaign)
    output += dash + " " + info_line(test_campaign, theme) + "\n"
    output += ptheme(" " + arrow + " Passed=%(passed)i\n" % test_campaign)
    output += ftheme(" " + arrow + " Failed=%(failed)i\n" % test_campaign)
    output += "%(headcomments)s\n" % test_campaign

    for testset in test_campaign:
        if any(t.expand for t in testset):
            output += "######\n## %(name)s\n######\n%(comments)s\n\n" % testset
            for t in testset:
                if t.expand:
                    output += "###(%(num)03i)=[%(result)s] %(name)s\n%(comments)s\n%(output)s\n\n" % t  # noqa: E501

    return output


def campaign_to_ANSI(test_campaign, theme):
    return campaign_to_TEXT(test_campaign, theme)


def campaign_to_xUNIT(test_campaign):
    output = '<?xml version="1.0" encoding="UTF-8" ?>\n<testsuite>\n'
    for testset in test_campaign:
        for t in testset:
            output += ' <testcase classname="%s"\n' % testset.name.replace('"', ' ')  # noqa: E501
            output += '           name="%s"\n' % t.name.replace('"', ' ')  # noqa: E501
            output += '           duration="0">\n' % t
            if not t:
                output += '<error><![CDATA[%(output)s]]></error>\n' % t
            output += "</testcase>\n"
    output += '</testsuite>'
    return output


def campaign_to_HTML(test_campaign):
    output = """
<h1>%(title)s</h1>

<p>
""" % test_campaign

    if test_campaign.crc is not None and test_campaign.sha is not None:
        output += "CRC=<span class=crc>%(crc)s</span> SHA=<span class=crc>%(sha)s</span><br>" % test_campaign
    output += "<small><em>" + html_info_line(test_campaign) + "</em></small>"
    output += "".join([
        test_campaign.headcomments,
        "\n<p>",
        "PASSED=%(passed)i FAILED=%(failed)i" % test_campaign,
        " <span class=warn_interrupted>INTERRUPTED!</span>" if test_campaign.interrupted else "",
        "<p>\n\n",
    ])

    for testset in test_campaign:
        output += "<h2>" % testset
        if testset.crc is not None:
            output += "<span class=crc>%(crc)s</span> " % testset
        output += "%(name)s</h2>\n%(comments)s\n<ul>\n" % testset
        for t in testset:
            output += """<li class=%(result)s id="tst%(num)il">\n""" % t
            if t.expand == 2:
                output += """
<span id="tst%(num)i+" class="button%(result)s" onClick="show('tst%(num)i')" style="POSITION: absolute; VISIBILITY: hidden;">+%(num)03i+</span>
<span id="tst%(num)i-" class="button%(result)s" onClick="hide('tst%(num)i')">-%(num)03i-</span>
""" % t
            else:
                output += """
<span id="tst%(num)i+" class="button%(result)s" onClick="show('tst%(num)i')">+%(num)03i+</span>
<span id="tst%(num)i-" class="button%(result)s" onClick="hide('tst%(num)i')" style="POSITION: absolute; VISIBILITY: hidden;">-%(num)03i-</span>
""" % t
            if t.crc is not None:
                output += "<span class=crc>%(crc)s</span>\n" % t
            output += """%(name)s\n<span class="comment %(result)s" id="tst%(num)i" """ % t  # noqa: E501
            if t.expand < 2:
                output += """ style="POSITION: absolute; VISIBILITY: hidden;" """  # noqa: E501
            output += """><br>%(comments)s
<pre>
%(output)s</pre></span>
""" % t
        output += "\n</ul>\n\n"
    return output


def pack_html_campaigns(runned_campaigns, data, local=False, title=None):
    output = """
<html>
<head>
<title>%(title)s</title>
<h1>UTScapy tests</h1>

<span class=control_button onClick="hide_all('tst')">Shrink All</span>
<span class=control_button onClick="show_all('tst')">Expand All</span>
<span class=control_button onClick="show_passed('tst')">Expand Passed</span>
<span class=control_button onClick="show_failed('tst')">Expand Failed</span>

<p>
"""
    for test_campaign in runned_campaigns:
        for ts in test_campaign:
            for t in ts:
                output += """<span class=button%(result)s onClick="goto_id('tst%(num)il')">%(num)03i</span>\n""" % t

    output += """</p>\n\n
<link rel="stylesheet" href="%(UTscapy_css)s" type="text/css">
<script language="JavaScript" src="%(UTscapy_js)s" type="text/javascript"></script>
</head>
<body>
%(data)s
</body></html>
"""
    out_dict = {'data': data, 'title': title if title else "UTScapy tests"}
    if local:
        dirname = os.path.dirname(test_campaign.output_file)
        External_Files.UTscapy_js.write(dirname)
        External_Files.UTscapy_css.write(dirname)
        out_dict.update(External_Files.get_local_dict())
    else:
        out_dict.update(External_Files.get_URL_dict())

    output %= out_dict
    return output


def campaign_to_LATEX(test_campaign):
    output = r"""
\chapter{%(title)s}
Run %%s on \date{%%s}
\begin{description}
\item[Passed:] %(passed)i
\item[Failed:] %(failed)i
\end{description}

%(headcomments)s

""" % test_campaign
    output %= latex_info_line(test_campaign)

    for testset in test_campaign:
        output += "\\section{%(name)s}\n\n%(comments)s\n\n" % testset
        for t in testset:
            t.comments = tex_escape(t.comments)
            if t.expand:
                output += r"""\subsection{%(name)s}

Test result: \textbf{%(result)s}\newline

%(comments)s
\begin{alltt}
%(output)s
\end{alltt}

""" % t

    return output


def pack_latex_campaigns(runned_campaigns, data, local=False, title=None):
    output = r"""
\documentclass{report}
\usepackage{alltt}
\usepackage{xcolor}
\usepackage{a4wide}
\usepackage{hyperref}

\title{%(title)s}

\begin{document}
\maketitle
\tableofcontents

%(data)s
\end{document}\n
"""

    out_dict = {'data': data, 'title': title if title else "UTScapy tests"}

    output %= out_dict
    return output


# USAGE #

def usage():
    print("""Usage: UTscapy [-m module] [-f {text|ansi|HTML|LaTeX|xUnit|live}] [-o output_file]
               [-t testfile] [-T testfile] [-k keywords [-k ...]] [-K keywords [-K ...]]
               [-l] [-b] [-d|-D] [-F] [-q[q]] [-i] [-P preexecute_python_code]
               [-c configfile]
-t\t\t: provide test files (can be used many times)
-T\t\t: if -t is used with *, remove a specific file (can be used many times)
-l\t\t: generate local .js and .css files
-F\t\t: expand only failed tests
-b\t\t: don't stop at the first failed campaign
-d\t\t: dump campaign
-D\t\t: dump campaign and stop
-R\t\t: dump campaign as reStructuredText
-C\t\t: don't calculate CRC and SHA
-c\t\t: load a .utsc config file
-i\t\t: drop into Python interpreter if test failed
-q\t\t: quiet mode
-qq\t\t: [silent mode]
-x\t\t: use pyannotate
-n <testnum>\t: only tests whose numbers are given (eg. 1,3-7,12)
-N\t\t: force non root
-m <module>\t: additional module to put in the namespace
-k <kw1>,<kw2>,...\t: include only tests with one of those keywords (can be used many times)
-K <kw1>,<kw2>,...\t: remove tests with one of those keywords (can be used many times)
-P <preexecute_python_code>
""")
    raise SystemExit


#    MAIN    #

def execute_campaign(TESTFILE, OUTPUTFILE, PREEXEC, NUM, KW_OK, KW_KO, DUMP, DOCS,
                     FORMAT, VERB, ONLYFAILED, CRC, INTERPRETER,
                     autorun_func, theme, pos_begin=0,
                     scapy_ses=None):  # noqa: E501
    # Parse test file
    try:
        test_campaign = parse_campaign_file(TESTFILE)
    except ValueError as ex:
        print(
            theme.red("Error while parsing '%s': '%s'" % (TESTFILE.name, ex))
        )
        sys.exit(1)

    # Report parameters
    if PREEXEC:
        test_campaign.preexec = PREEXEC

    # Compute campaign CRC and SHA
    if CRC:
        compute_campaign_digests(test_campaign)

    # Filter out unwanted tests
    filter_tests_on_numbers(test_campaign, NUM)
    for k in KW_OK:
        filter_tests_keep_on_keywords(test_campaign, k)
    for k in KW_KO:
        filter_tests_remove_on_keywords(test_campaign, k)

    remove_empty_testsets(test_campaign)

    # Dump campaign
    if DUMP:
        dump_campaign(test_campaign)
        if DUMP > 1:
            sys.exit()

    # Dump campaign as reStructuredText
    if DOCS:
        docs_campaign(test_campaign)
        sys.exit()

    # Run tests
    test_campaign.output_file = OUTPUTFILE
    result = run_campaign(
        test_campaign, autorun_func[FORMAT], theme,
        drop_to_interpreter=INTERPRETER,
        verb=VERB,
        scapy_ses=scapy_ses
    )

    # Shrink passed
    if ONLYFAILED:
        for t in test_campaign.all_tests():
            if t:
                t.expand = 0
            else:
                t.expand = 2

    # Generate report
    if FORMAT == Format.TEXT:
        output = campaign_to_TEXT(test_campaign, theme)
    elif FORMAT == Format.ANSI:
        output = campaign_to_ANSI(test_campaign, theme)
    elif FORMAT == Format.HTML:
        test_campaign.startNum(pos_begin)
        output = campaign_to_HTML(test_campaign)
    elif FORMAT == Format.LATEX:
        output = campaign_to_LATEX(test_campaign)
    elif FORMAT == Format.XUNIT:
        output = campaign_to_xUNIT(test_campaign)
    elif FORMAT == Format.LIVE:
        output = ""

    return output, (result == 0), test_campaign


def resolve_testfiles(TESTFILES):
    for tfile in TESTFILES[:]:
        if "*" in tfile:
            TESTFILES.remove(tfile)
            TESTFILES.extend(sorted(glob.glob(tfile)))
    return TESTFILES


def main():
    argv = sys.argv[1:]
    logger = logging.getLogger("scapy")
    logger.addHandler(logging.StreamHandler())

    import scapy
    print(dash + " UTScapy - Scapy %s - %s" % (
        scapy.__version__, sys.version.split(" ")[0]
    ))

    # Parse arguments

    FORMAT = Format.ANSI
    OUTPUTFILE = sys.stdout
    LOCAL = 0
    NUM = None
    NON_ROOT = False
    KW_OK = []
    KW_KO = []
    DUMP = 0
    DOCS = 0
    CRC = True
    BREAKFAILED = True
    ONLYFAILED = False
    VERB = 3
    GLOB_PREEXEC = ""
    PREEXEC_DICT = {}
    MODULES = []
    TESTFILES = []
    ANNOTATIONS_MODE = False
    INTERPRETER = False
    try:
        opts = getopt.getopt(argv, "o:t:T:c:f:hbln:m:k:K:DRdCiFqNP:s:x")
        for opt, optarg in opts[0]:
            if opt == "-h":
                usage()
            elif opt == "-b":
                BREAKFAILED = False
            elif opt == "-F":
                ONLYFAILED = True
            elif opt == "-q":
                VERB -= 1
            elif opt == "-D":
                DUMP = 2
            elif opt == "-R":
                DOCS = 1
            elif opt == "-d":
                DUMP = 1
            elif opt == "-C":
                CRC = False
            elif opt == "-i":
                INTERPRETER = True
            elif opt == "-x":
                ANNOTATIONS_MODE = True
            elif opt == "-P":
                GLOB_PREEXEC += "\n" + optarg
            elif opt == "-f":
                try:
                    FORMAT = Format.from_string(optarg)
                except KeyError as msg:
                    raise getopt.GetoptError("Unknown output format %s" % msg)
            elif opt == "-t":
                TESTFILES.append(optarg)
                TESTFILES = resolve_testfiles(TESTFILES)
            elif opt == "-T":
                TESTFILES.remove(optarg)
            elif opt == "-c":
                data = parse_config_file(optarg, VERB)
                BREAKFAILED = data.breakfailed
                ONLYFAILED = data.onlyfailed
                VERB = data.verb
                DUMP = data.dump
                CRC = data.crc
                PREEXEC_DICT = data.preexec
                GLOB_PREEXEC = data.global_preexec
                OUTPUTFILE = data.outfile
                TESTFILES = data.testfiles
                LOCAL = 1 if data.local else 0
                NUM = data.num
                MODULES = data.modules
                KW_OK.extend(data.kw_ok)
                KW_KO.extend(data.kw_ko)
                try:
                    FORMAT = Format.from_string(data.format)
                except KeyError as msg:
                    raise getopt.GetoptError("Unknown output format %s" % msg)
                TESTFILES = resolve_testfiles(TESTFILES)
                for testfile in resolve_testfiles(data.remove_testfiles):
                    try:
                        TESTFILES.remove(testfile)
                    except ValueError:
                        error_m = "Cannot remove %s from test files" % testfile
                        raise getopt.GetoptError(error_m)
            elif opt == "-o":
                OUTPUTFILE = optarg
                if not os.access(os.path.dirname(os.path.abspath(OUTPUTFILE)), os.W_OK):
                    raise getopt.GetoptError("Cannot write to file %s" % OUTPUTFILE)
            elif opt == "-l":
                LOCAL = 1
            elif opt == "-n":
                NUM = []
                for v in (x.strip() for x in optarg.split(",")):
                    try:
                        NUM.append(int(v))
                    except ValueError:
                        v1, v2 = [int(e) for e in v.split('-', 1)]
                        NUM.extend(range(v1, v2 + 1))
            elif opt == "-N":
                NON_ROOT = True
            elif opt == "-m":
                MODULES.append(optarg)
            elif opt == "-k":
                KW_OK.extend(optarg.split(","))
            elif opt == "-K":
                KW_KO.extend(optarg.split(","))

    except getopt.GetoptError as msg:
        print("ERROR:", msg)
        raise SystemExit

    if FORMAT in [Format.LIVE, Format.ANSI]:
        theme = DefaultTheme()
    else:
        theme = BlackAndWhite()

    # Disable tests if needed

    # Discard Python3 tests when using Python2
    if six.PY2:
        KW_KO.append("python3_only")
        if VERB > 2:
            print(" " + arrow + " Python 2 mode")
    try:
        if NON_ROOT or os.getuid() != 0:  # Non root
            # Discard root tests
            KW_KO.append("needs_root")
            if VERB > 2:
                print(" " + arrow + " Non-root mode")
    except AttributeError:
        pass

    if conf.use_pcap or WINDOWS:
        KW_KO.append("not_libpcap")
        if VERB > 2:
            print(" " + arrow + " libpcap mode")

    KW_KO.append("disabled")

    # Process extras
    if six.PY2 and DARWIN:
        # On MacOS 12, Python 2.7 find_library is broken
        KW_KO.append("libpcap")

    if ANNOTATIONS_MODE:
        try:
            from pyannotate_runtime import collect_types
        except ImportError:
            raise ImportError("Please install pyannotate !")
        collect_types.init_types_collection()
        collect_types.start()

    if VERB > 2:
        print(" " + arrow + " Booting scapy...")
    try:
        from scapy import all as scapy
    except Exception as e:
        print("[CRITICAL]: Cannot import Scapy: %s" % e)
        traceback.print_exc()
        sys.exit(1)  # Abort the tests

    for m in MODULES:
        try:
            mod = import_module(m)
            six.moves.builtins.__dict__.update(mod.__dict__)
        except ImportError as e:
            raise getopt.GetoptError("cannot import [%s]: %s" % (m, e))

    autorun_func = {
        Format.TEXT: scapy.autorun_get_text_interactive_session,
        Format.ANSI: scapy.autorun_get_ansi_interactive_session,
        Format.HTML: scapy.autorun_get_html_interactive_session,
        Format.LATEX: scapy.autorun_get_latex_interactive_session,
        Format.XUNIT: scapy.autorun_get_text_interactive_session,
        Format.LIVE: scapy.autorun_get_live_interactive_session,
    }

    if VERB > 2:
        print(" " + arrow + " Discovering tests files...")

    glob_output = ""
    glob_result = 0
    glob_title = None

    UNIQUE = len(TESTFILES) == 1

    # Resolve tags and asterix
    for prex in six.iterkeys(copy.copy(PREEXEC_DICT)):
        if "*" in prex:
            pycode = PREEXEC_DICT[prex]
            del PREEXEC_DICT[prex]
            for gl in glob.iglob(prex):
                _pycode = pycode.replace("%name%", os.path.splitext(os.path.split(gl)[1])[0])  # noqa: E501
                PREEXEC_DICT[gl] = _pycode

    pos_begin = 0

    runned_campaigns = []

    from scapy.main import _scapy_builtins
    scapy_ses = _scapy_builtins()
    import_UTscapy_tools(scapy_ses)

    # Execute all files
    for TESTFILE in TESTFILES:
        if VERB > 2:
            print(theme.green(dash + " Loading: %s" % TESTFILE))
        PREEXEC = PREEXEC_DICT[TESTFILE] if TESTFILE in PREEXEC_DICT else GLOB_PREEXEC
        with open(TESTFILE) as testfile:
            output, result, campaign = execute_campaign(
                testfile, OUTPUTFILE, PREEXEC, NUM, KW_OK, KW_KO, DUMP, DOCS,
                FORMAT, VERB, ONLYFAILED, CRC, INTERPRETER,
                autorun_func, theme,
                pos_begin=pos_begin,
                scapy_ses=copy.copy(scapy_ses)
            )
        runned_campaigns.append(campaign)
        pos_begin = campaign.end_pos
        if UNIQUE:
            glob_title = campaign.title
        glob_output += output
        if not result:
            glob_result = 1
            if BREAKFAILED:
                break

    if VERB > 2:
        print(
            checkmark + " All campaigns executed. Writing output..."
        )

    if ANNOTATIONS_MODE:
        collect_types.stop()
        collect_types.dump_stats("pyannotate_results")

    # Concenate outputs
    if FORMAT == Format.HTML:
        glob_output = pack_html_campaigns(runned_campaigns, glob_output, LOCAL, glob_title)
    if FORMAT == Format.LATEX:
        glob_output = pack_latex_campaigns(runned_campaigns, glob_output, LOCAL, glob_title)

    # Write the final output
    # Note: on Python 2, we force-encode to ignore ascii errors
    # on Python 3, we need to detect the type of stream
    if OUTPUTFILE == sys.stdout:
        print(glob_output, file=OUTPUTFILE)
    else:
        with open(OUTPUTFILE, "wb") as f:
            f.write(glob_output.encode("utf8", "ignore")
                    if 'b' in f.mode or six.PY2 else glob_output)

    # Print end message
    if VERB > 2:
        if glob_result == 0:
            print(theme.green("UTscapy ended successfully"))
        else:
            print(theme.red("UTscapy ended with error code %s" % glob_result))

    # Check active threads
    if VERB > 2:
        if threading.active_count() > 1:
            print("\nWARNING: UNFINISHED THREADS")
            print(threading.enumerate())
        import multiprocessing
        processes = multiprocessing.active_children()
        if processes:
            print("\nWARNING: UNFINISHED PROCESSES")
            print(processes)

    sys.stdout.flush()

    # Return state
    return glob_result


if __name__ == "__main__":
    if sys.warnoptions:
        with warnings.catch_warnings(record=True) as cw:
            warnings.resetwarnings()
            # Let's discover the garbage waste
            warnings.simplefilter('error')
            print("### Warning mode enabled ###")
            res = main()
            if cw:
                res = 1
        sys.exit(res)
    else:
        sys.exit(main())
