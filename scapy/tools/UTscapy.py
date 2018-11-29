# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

# flake8: noqa: E501

"""
Unit testing infrastructure for Scapy
"""

from __future__ import absolute_import
from __future__ import print_function
import sys
import getopt
import glob
import importlib
import hashlib
import copy
import bz2
import base64
import os.path
import time
import traceback
import warnings
import zlib

from scapy.consts import WINDOWS
import scapy.modules.six as six
from scapy.modules.six.moves import range
from scapy.compat import base64_bytes


#   Util class   #

class Bunch:
    __init__ = lambda self, **kw: setattr(self, '__dict__', kw)

def retry_test(func):
    """Retries the passed function 3 times before failing"""
    success = False
    ex = Exception("Unknown")
    for i in six.moves.range(3):
        try:
            result = func()
        except Exception as e:
            time.sleep(1)
            ex = e
        else:
            success = True
            break
    if not success:
        raise ex
    assert success
    return result

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


#    TEST CLASSES    #

class TestClass:
    def __getitem__(self, item):
        return getattr(self, item)

    def add_keywords(self, kws):
        if isinstance(kws, six.string_types):
            kws = [kws]
        for kwd in kws:
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
        self.result = "passed" # make instance True at init to have a different truth value than None
        self.output = ""
        self.num = -1
        self.keywords = set()
        self.crc = None
        self.expand = 1

    def decode(self):
        if six.PY2:
            self.test = self.test.decode("utf8", "ignore")
            self.output = self.output.decode("utf8", "ignore")
            self.comments = self.comments.decode("utf8", "ignore")
            self.result = self.result.decode("utf8", "ignore")

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
      "verb": 2,
      "dump": 0,
      "crc": true,
      "scapy": "scapy",
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
    import json
    import unicodedata
    with open(config_path) as config_file:
        data = json.load(config_file, encoding="utf8")
        if verb > 2:
            print("### Loaded config file", config_path, file=sys.stderr)

    def get_if_exist(key, default):
        return data[key] if key in data else default
    return Bunch(testfiles=get_if_exist("testfiles", []),
                 breakfailed=get_if_exist("breakfailed", True),
                 remove_testfiles=get_if_exist("remove_testfiles", []),
                 onlyfailed=get_if_exist("onlyfailed", False),
                 verb=get_if_exist("verb", 3),
                 dump=get_if_exist("dump", 0), crc=get_if_exist("crc", 1),
                 scapy=get_if_exist("scapy", "scapy"),
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

    for l in campaign_file.readlines():
        if l[0] == '#':
            continue
        if l[0] == "~":
            (test or testset or test_campaign).add_keywords(l[1:].split())
        elif l[0] == "%":
            test_campaign.title = l[1:].strip()
        elif l[0] == "+":
            testset = TestSet(l[1:].strip())
            test_campaign.add_testset(testset)
            test = None
        elif l[0] == "=":
            test = UnitTest(l[1:].strip())
            test.num = testnb
            testnb += 1
            testset.add_test(test)
        elif l[0] == "*":
            if test is not None:
                test.comments += l[1:]
            elif testset is not None:
                testset.comments += l[1:]
            else:
                test_campaign.headcomments += l[1:]
        else:
            if test is None:
                if l.strip():
                    print("Unknown content [%s]" % l.strip(), file=sys.stderr)
            else:
                test.test += l
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


def filter_tests_keep_on_keywords(test_campaign, kw):
    def kw_match(lst, kw):
        for k in lst:
            if k in kw:
                return True
        return False

    if kw:
        for ts in test_campaign:
            ts.tests = [t for t in ts.tests if kw_match(t.keywords, kw)]


def filter_tests_remove_on_keywords(test_campaign, kw):
    def kw_match(lst, kw):
        for k in kw:
            if k in lst:
                return True
        return False

    if kw:
        for ts in test_campaign:
            ts.tests = [t for t in ts.tests if not kw_match(t.keywords, kw)]


def remove_empty_testsets(test_campaign):
    test_campaign.campaign = [ts for ts in test_campaign.campaign if ts.tests]


#### RUN TEST #####

def run_test(test, get_interactive_session, verb=3, ignore_globals=None):
    test.output, res = get_interactive_session(test.test.strip(), ignore_globals=ignore_globals)
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
        test.decode()
        if verb > 1:
            print("%(result)6s %(crc)s %(name)s" % test, file=sys.stderr)

    return bool(test)

#### RUN CAMPAIGN #####

def run_campaign(test_campaign, get_interactive_session, verb=3, ignore_globals=None):  # noqa: E501
    passed = failed = 0
    if test_campaign.preexec:
        test_campaign.preexec_output = get_interactive_session(test_campaign.preexec.strip(), ignore_globals=ignore_globals)[0]
    try:
        for i, testset in enumerate(test_campaign):
            for j, t in enumerate(testset):
                if run_test(t, get_interactive_session, verb):
                    passed += 1
                else:
                    failed += 1
    except KeyboardInterrupt:
        failed += 1
        testset.trunc(j+1)
        test_campaign.trunc(i+1)
        test_campaign.interrupted = True
        if verb:
            print("Campaign interrupted!", file=sys.stderr)

    test_campaign.passed = passed
    test_campaign.failed = failed
    if verb:
        print("Campaign CRC=%(crc)s  SHA=%(sha)s" % test_campaign, file=sys.stderr)  # noqa: E501
        print("PASSED=%i FAILED=%i" % (passed, failed), file=sys.stderr)
    return failed


#    INFO LINES    #

def info_line(test_campaign):
    filename = test_campaign.filename
    if filename is None:
        return "Run %s by UTscapy" % time.ctime()
    else:
        return "Run %s from [%s] by UTscapy" % (time.ctime(), filename)


def html_info_line(test_campaign):
    filename = test_campaign.filename
    if filename is None:
        return """Run %s by <a href="http://www.secdev.org/projects/UTscapy/">UTscapy</a><br>""" % time.ctime()  # noqa: E501
    else:
        return """Run %s from [%s] by <a href="http://www.secdev.org/projects/UTscapy/">UTscapy</a><br>""" % (time.ctime(), filename)  # noqa: E501


#    CAMPAIGN TO something    #

def campaign_to_TEXT(test_campaign):
    output="%(title)s\n" % test_campaign
    output += "-- "+info_line(test_campaign)+"\n\n"
    output += "Passed=%(passed)i\nFailed=%(failed)i\n\n%(headcomments)s\n" % test_campaign

    for testset in test_campaign:
        if any(t.expand for t in testset):
            output += "######\n## %(name)s\n######\n%(comments)s\n\n" % testset
            for t in testset:
                if t.expand:
                    output += "###(%(num)03i)=[%(result)s] %(name)s\n%(comments)s\n%(output)s\n\n" % t  # noqa: E501

    return output


def campaign_to_ANSI(test_campaign):
    output="%(title)s\n" % test_campaign
    output += "-- "+info_line(test_campaign)+"\n\n"
    output += "Passed=%(passed)i\nFailed=%(failed)i\n\n%(headcomments)s\n" % test_campaign

    for testset in test_campaign:
        if any(t.expand for t in testset):
            output += "######\n## %(name)s\n######\n%(comments)s\n\n" % testset
            for t in testset:
                if t.expand:
                    output += "###(%(num)03i)=[%(result)s] %(name)s\n%(comments)s\n%(output)s\n\n" % t  # noqa: E501

    return output


def campaign_to_xUNIT(test_campaign):
    output = '<?xml version="1.0" encoding="UTF-8" ?>\n<testsuite>\n'
    for testset in test_campaign:
        for t in testset:
            output += ' <testcase classname="%s"\n' % testset.name.encode("string_escape").replace('"', ' ')  # noqa: E501
            output += '           name="%s"\n' % t.name.encode("string_escape").replace('"', ' ')  # noqa: E501
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
    output += "<small><em>"+html_info_line(test_campaign)+"</em></small>"
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
    output = r"""\documentclass{report}
\usepackage{alltt}
\usepackage{xcolor}
\usepackage{a4wide}
\usepackage{hyperref}

\title{%(title)s}
\date{%%s}

\begin{document}
\maketitle
\tableofcontents

\begin{description}
\item[Passed:] %(passed)i
\item[Failed:] %(failed)i
\end{description}

%(headcomments)s

""" % test_campaign
    output %= info_line(test_campaign)

    for testset in test_campaign:
        output += "\\chapter{%(name)s}\n\n%(comments)s\n\n" % testset
        for t in testset:
            if t.expand:
                output += r"""\section{%(name)s}

[%(num)03i] [%(result)s]

%(comments)s
\begin{alltt}
%(output)s
\end{alltt}

""" % t

    output += "\\end{document}\n"
    return output


#### USAGE ####

def usage():
    print("""Usage: UTscapy [-m module] [-f {text|ansi|HTML|LaTeX}] [-o output_file]
               [-t testfile] [-T testfile] [-k keywords [-k ...]] [-K keywords [-K ...]]
               [-l] [-b] [-d|-D] [-F] [-q[q]] [-P preexecute_python_code]
               [-s /path/to/scapy] [-c configfile]
-t\t\t: provide test files (can be used many times)
-T\t\t: if -t is used with *, remove a specific file (can be used many times)
-l\t\t: generate local .js and .css files
-F\t\t: expand only failed tests
-b\t\t: stop at first failed campaign
-d\t\t: dump campaign
-D\t\t: dump campaign and stop
-C\t\t: don't calculate CRC and SHA
-s\t\t: path to scapy.py
-c\t\t: load a .utsc config file
-q\t\t: quiet mode
-qq\t\t: [silent mode]
-n <testnum>\t: only tests whose numbers are given (eg. 1,3-7,12)
-m <module>\t: additional module to put in the namespace
-k <kw1>,<kw2>,...\t: include only tests with one of those keywords (can be used many times)
-K <kw1>,<kw2>,...\t: remove tests with one of those keywords (can be used many times)
-P <preexecute_python_code>
""", file=sys.stderr)
    raise SystemExit


#    MAIN    #

def execute_campaign(TESTFILE, OUTPUTFILE, PREEXEC, NUM, KW_OK, KW_KO, DUMP,
                     FORMAT, VERB, ONLYFAILED, CRC, autorun_func, pos_begin=0, ignore_globals=None):  # noqa: E501
    # Parse test file
    test_campaign = parse_campaign_file(TESTFILE)

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

    # Run tests
    test_campaign.output_file = OUTPUTFILE
    result = run_campaign(test_campaign, autorun_func[FORMAT], verb=VERB, ignore_globals=None)  # noqa: E501

    # Shrink passed
    if ONLYFAILED:
        for t in test_campaign.all_tests():
            if t:
                t.expand = 0
            else:
                t.expand = 2

    # Generate report
    if FORMAT == Format.TEXT:
        output = campaign_to_TEXT(test_campaign)
    elif FORMAT == Format.ANSI:
        output = campaign_to_ANSI(test_campaign)
    elif FORMAT == Format.HTML:
        test_campaign.startNum(pos_begin)
        output = campaign_to_HTML(test_campaign)
    elif FORMAT == Format.LATEX:
        output = campaign_to_LATEX(test_campaign)
    elif FORMAT == Format.XUNIT:
        output = campaign_to_xUNIT(test_campaign)

    return output, (result == 0), test_campaign


def resolve_testfiles(TESTFILES):
    for tfile in TESTFILES[:]:
        if "*" in tfile:
            TESTFILES.remove(tfile)
            TESTFILES.extend(glob.glob(tfile))
    return TESTFILES


def main(argv):
    ignore_globals = list(six.moves.builtins.__dict__.keys())

    # Parse arguments

    FORMAT = Format.ANSI
    OUTPUTFILE = sys.stdout
    LOCAL = 0
    NUM = None
    KW_OK = []
    KW_KO = []
    DUMP = 0
    CRC = True
    BREAKFAILED = True
    ONLYFAILED = False
    VERB = 3
    GLOB_PREEXEC = ""
    PREEXEC_DICT = {}
    SCAPY = "scapy"
    MODULES = []
    TESTFILES = []
    try:
        opts = getopt.getopt(argv, "o:t:T:c:f:hbln:m:k:K:DdCFqP:s:")
        for opt, optarg in opts[0]:
            if opt == "-h":
                usage()
            elif opt == "-b":
                BREAKFAILED =  True
            elif opt == "-F":
                ONLYFAILED = True
            elif opt == "-q":
                VERB -= 1
            elif opt == "-D":
                DUMP = 2
            elif opt == "-d":
                DUMP = 1
            elif opt == "-C":
                CRC = False
            elif opt == "-s":
                SCAPY = optarg
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
                SCAPY = data.scapy
                PREEXEC_DICT = data.preexec
                GLOB_PREEXEC = data.global_preexec
                OUTPUTFILE = data.outfile
                TESTFILES = data.testfiles
                LOCAL = 1 if data.local else 0
                NUM = data.num
                MODULES = data.modules
                KW_OK = [data.kw_ok]
                KW_KO = [data.kw_ko]
                try:
                    FORMAT = Format.from_string(data.format)
                except KeyError as msg:
                    raise getopt.GetoptError("Unknown output format %s" % msg)
                TESTFILES = resolve_testfiles(TESTFILES)
                for testfile in resolve_testfiles(data.remove_testfiles):
                    TESTFILES.remove(testfile)
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
            elif opt == "-m":
                MODULES.append(optarg)
            elif opt == "-k":
                KW_OK.append(optarg.split(","))
            elif opt == "-K":
                KW_KO.append(optarg.split(","))

        # Discard Python3 tests when using Python2
        if six.PY2:
            KW_KO.append(["python3_only"])

        if VERB > 2:
            print("### Booting scapy...", file=sys.stderr)
        try:
            from scapy import all as scapy
        except Exception as e:
            print("[CRITICAL]: Cannot import Scapy: %s" % e, file=sys.stderr)
            traceback.print_exc()
            sys.exit(1)  # Abort the tests

        for m in MODULES:
            try:
                mod = import_module(m)
                six.moves.builtins.__dict__.update(mod.__dict__)
            except ImportError as e:
                raise getopt.GetoptError("cannot import [%s]: %s" % (m, e))

        if WINDOWS:
            from scapy.arch.windows import route_add_loopback
            route_add_loopback()

        # Add SCAPY_ROOT_DIR environment variable, used for tests
        os.environ['SCAPY_ROOT_DIR'] = os.environ.get("PWD", os.getcwd())

    except getopt.GetoptError as msg:
        print("ERROR:", msg, file=sys.stderr)
        raise SystemExit

    autorun_func = {
        Format.TEXT: scapy.autorun_get_text_interactive_session,
        Format.ANSI: scapy.autorun_get_ansi_interactive_session,
        Format.HTML: scapy.autorun_get_html_interactive_session,
        Format.LATEX: scapy.autorun_get_latex_interactive_session,
        Format.XUNIT: scapy.autorun_get_text_interactive_session,
    }

    if VERB > 2:
        print("### Starting tests...", file=sys.stderr)

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
    # Execute all files
    for TESTFILE in TESTFILES:
        if VERB > 2:
            print("### Loading:", TESTFILE, file=sys.stderr)
        PREEXEC = PREEXEC_DICT[TESTFILE] if TESTFILE in PREEXEC_DICT else GLOB_PREEXEC
        with open(TESTFILE) as testfile:
            output, result, campaign = execute_campaign(testfile, OUTPUTFILE,
                                                        PREEXEC, NUM, KW_OK, KW_KO,
                                                        DUMP, FORMAT, VERB, ONLYFAILED,
                                                        CRC, autorun_func, pos_begin,
                                                        ignore_globals)
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
        print("### Writing output...", file=sys.stderr)
    # Concenate outputs
    if FORMAT == Format.HTML:
        glob_output = pack_html_campaigns(runned_campaigns, glob_output, LOCAL, glob_title)

    # Write the final output
    # Note: on Python 2, we force-encode to ignore ascii errors
    # on Python 3, we need to detect the type of stream
    if OUTPUTFILE == sys.stdout:
        OUTPUTFILE.write(glob_output.encode("utf8", "ignore")
                         if 'b' in OUTPUTFILE.mode or six.PY2 else glob_output)
    else:
        with open(OUTPUTFILE, "wb") as f:
            f.write(glob_output.encode("utf8", "ignore")
                    if 'b' in f.mode or six.PY2 else glob_output)

    # Delete scapy's test environment vars
    del os.environ['SCAPY_ROOT_DIR']

    # Return state
    return glob_result


if __name__ == "__main__":
    if sys.warnoptions:
        with warnings.catch_warnings(record=True) as cw:
            warnings.resetwarnings()
            # Let's discover the garbage waste
            warnings.simplefilter('error')
            print("### Warning mode enabled ###")
            res = main(sys.argv[1:])
            if cw:
                res = 1
        sys.exit(res)
    else:
        sys.exit(main(sys.argv[1:]))
