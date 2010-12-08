## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

"""
Unit testing infrastructure for Scapy
"""

import sys,getopt,imp
import bz2, base64, os.path, time, traceback, zlib, sha


#### Import tool ####

def import_module(name):
    name = os.path.realpath(name)
    thepath = os.path.dirname(name)
    name = os.path.basename(name)
    if name.endswith(".py"):
        name = name[:-3]
    f,path,desc = imp.find_module(name,[thepath])
    
    try:
        return imp.load_module(name, f, path, desc)
    finally:
        if f:
            f.close()


#### INTERNAL/EXTERNAL FILE EMBEDDING ####

class File:
    def __init__(self, name, URL, local):
        self.name = name
        self.local = local
        self.URL = URL
    def get_local(self):
        return bz2.decompress(base64.decodestring(self.local))
    def get_URL(self):
        return URL
    def write(self, dir):
        if dir:
            dir += "/"
        open(dir+self.name,"w").write(self.get_local())

        
# Embed a base64 encoded bziped version of js and css files
# to work if you can't reach Internet.
class External_Files:
    UTscapy_js = File("UTscapy.js", "http://www.secdev.org/projects/UTscapy/UTscapy.js",
"""QlpoOTFBWSZTWWVijKQAAXxfgERUYOvAChIhBAC/79+qQAH8AFA0poANAMjQAAAG
ABo0NGEZNBo00BhgAaNDRhGTQaNNAYFURJinplGaKbRkJiekzSenqmpA0Gm1LFMp
RUklVQlK9WUTZYpNFI1IiEWEFT09Sfj5uO+qO6S5DQwKIxM92+Zku94wL6V/1KTK
an2c66Ug6SmVKy1ZIrgauxMVLF5xLH0lJRQuKlqLF10iatlTzqvw7S9eS3+h4lu3
GZyMgoOude3NJ1pQy8eo+X96IYZw+ynehsiPj73m0rnvQ3QXZ9BJQiZQYQ5/uNcl
2WOlC5vyQqV/BWsnr2NZYLYXQLDs/Bffk4ZfR4/SH6GfA5Xlek4xHNHqbSsRbREO
gueXo3kcYi94K6hSO3ldD2O/qJXOFqJ8o3TE2aQahxtQpCVUKQMvODHwu2YkaORY
ZC6gihEallcHDIAtRPScBACAJnUggYhLDX6DEko7nC9GvAw5OcEkiyDUbLdiGCzD
aXWMC2DuQ2Y6sGf6NcRuON7QSbhHsPc4KKmZ/xdyRThQkGVijKQ=""")
    UTscapy_css = File("UTscapy.css","http://www.secdev.org/projects/UTscapy/UTscapy.css",
"""QlpoOTFBWSZTWTbBCNEAAE7fgHxwSB//+Cpj2QC//9/6UAR+63dxbNzO3ccmtGEk
pM0m1I9E/Qp6g9Q09TNQ9QDR6gMgAkiBFG9U9TEGRkGgABoABoBmpJkRAaAxD1AN
Gh6gNADQBzAATJgATCYJhDAEYAEiQkwIyJk0n6qenpqeoaMUeo9RgIxp6pX78kfx
Jx4MUhDHKEb2pJAYAelG1cybiZBBDipH8ocxNyHDAqTUxiQmIAEDE3ApIBUUECAT
7Lvlf4xA/sVK0QHkSlYtT0JmErdOjx1v5NONPYSjrIhQnbl1MbG5m+InMYmVAWJp
uklD9cNdmQv2YigxbEtgUrsY2pDDV/qMT2SHnHsViu2rrp2LA01YJIHZqjYCGIQN
sGNobFxAYHLqqMOj9TI2Y4GRpRCUGu82PnMnXUBgDSkTY4EfmygaqvUwbGMbPwyE
220Q4G+sDvw7+6in3CAOS634pcOEAdREUW+QqMjvWvECrGISo1piv3vqubTGOL1c
ssrFnnSfU4T6KSCbPs98HJ2yjWN4i8Bk5WrM/JmELLNeZ4vgMkA4JVQInNnWTUTe
gmMSlJd/b7JuRwiM5RUzXOBTa0e3spO/rsNJiylu0rCxygdRo2koXdSJzmUVjJUm
BOFIkUKq8LrE+oT9h2qUqqUQ25fGV7e7OFkpmZopqUi0WeIBzlXdYY0Zz+WUJUTC
RC+CIPFIYh1RkopswMAop6ZjuZKRqR0WNuV+rfuF5aCXPpxAm0F14tPyhf42zFMT
GJUMxxowJnoauRq4xGQk+2lYFxbQ0FiC43WZSyYLHMuo5NTJ92QLAgs4FgOyZQqQ
xpsGKMA0cIisNeiootpnlWQvkPzNGUTPg8jqkwTvqQLguZLKJudha1hqfBib1IfO
LNChcU6OqF+3wyPKg5Y5oSbSJPAMcRDANwmS2i9oZm6vsD1pLkWtFGbAkEjjCuEU
W1ev1IsF2UVmWYFtJkqLT708ApUBK/ig3rbJWSq7RGQd3sSrOKu3lyKzTBdkXK2a
BGLV5dS1XURdKxaRkMplLLQxsimBYZEAa8KQkYyI+4EagMqycRR7RgwtZFxJSu0T
1q5wS2JG82iETHplbNj8DYo9IkmKzNAiw4FxK8bRfIYvwrbshbEagL11AQJFsqeZ
WeXDoWEx2FMyyZRAB5QyCFnwYtwtWAQmmITY8aIM2SZyRnHH9Wi8+Sr2qyCscFYo
vzM985aHXOHAxQN2UQZbQkUv3D4Vc+lyvalAffv3Tyg4ks3a22kPXiyeCGweviNX
0K8TKasyOhGsVamTUAZBXfQVw1zmdS4rHDnbHgtIjX3DcCt6UIr0BHTYjdV0JbPj
r1APYgXihjQwM2M83AKIhwQQJv/F3JFOFCQNsEI0QA==""")
    def get_local_dict(cls):
        return dict(map(lambda (x,y): (x, y.name),  filter(lambda (x,y): isinstance(y, File), cls.__dict__.items())))
    get_local_dict = classmethod(get_local_dict)
    def get_URL_dict(cls):
        return dict(map(lambda (x,y): (x, y.URL),  filter(lambda (x,y): isinstance(y, File), cls.__dict__.items())))
    get_URL_dict = classmethod(get_URL_dict)


#### HELPER CLASSES FOR PARAMETRING OUTPUT FORMAT ####

class EnumClass:
    def from_string(cls,x):
        return cls.__dict__[x.upper()]
    from_string = classmethod(from_string)
    
class Format(EnumClass):
    TEXT  = 1
    ANSI  = 2
    HTML  = 3
    LATEX = 4
    XUNIT = 5


#### TEST CLASSES ####

class TestClass:
    def __getitem__(self, item):
        return getattr(self, item)
    def add_keywords(self, kw):
        if kw is str:
            self.keywords.append(kw)
        else:
            self.keywords += kw

class TestCampaign(TestClass):
    def __init__(self, title):
        self.title = title
        self.filename = None
        self.headcomments = ""
        self.campaign = []
        self.keywords = []
        self.crc = None
        self.sha = None
        self.preexec = None
        self.preexec_output = None
    def add_testset(self, testset):
        self.campaign.append(testset)
    def __iter__(self):
        return self.campaign.__iter__()
    def all_tests(self):
        for ts in self:
            for t in ts:
                yield t

class TestSet(TestClass):
    def __init__(self, name):
        self.name = name
        self.set = []
        self.comments = ""
        self.keywords = []
        self.crc = None
        self.expand = 1
    def add_test(self, test):
        self.set.append(test)
    def __iter__(self):
        return self.set.__iter__()

class UnitTest(TestClass):
    def __init__(self, name):
        self.name = name
        self.test = ""
        self.comments = ""
        self.result = ""
        self.res = True  # must be True at init to have a different truth value than None
        self.output = ""
        self.num = -1
        self.keywords = []
        self.crc = None
        self.expand = 1
    def __nonzero__(self):
        return self.res


#### PARSE CAMPAIGN ####

def parse_campaign_file(campaign_file):
    test_campaign = TestCampaign("Test campaign")
    test_campaign.filename=  campaign_file.name
    testset = None
    test = None
    testnb = 0

    for l in campaign_file.readlines():
        if l[0] == '#':
            continue
        if l[0] == "~":
            (test or testset or campaign_file).add_keywords(l[1:].split())
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
                    print >>sys.stderr, "Unkonwn content [%s]" % l.strip()
            else:
                test.test += l
    return test_campaign

def dump_campaign(test_campaign):
    print "#"*(len(test_campaign.title)+6)
    print "## %(title)s ##" % test_campaign
    print "#"*(len(test_campaign.title)+6)
    if test_campaign.sha and test_campaign.crc:
        print "CRC=[%(crc)s] SHA=[%(sha)s]" % test_campaign
    print "from file %(filename)s" % test_campaign
    print
    for ts in test_campaign:
        if ts.crc:
            print "+--[%s]%s(%s)--" % (ts.name,"-"*max(2,80-len(ts.name)-18),ts.crc)
        else:
            print "+--[%s]%s" % (ts.name,"-"*max(2,80-len(ts.name)-6))
        if ts.keywords:
            print "  kw=%s" % ",".join(ts.keywords)
        for t in ts:
            print "%(num)03i %(name)s" % t
            c = k = ""
            if t.keywords:
                k = "kw=%s" % ",".join(t.keywords)
            if t.crc:
                c = "[%(crc)s] " % t
            if c or k:
                print "    %s%s" % (c,k) 

#### COMPUTE CAMPAIGN DIGESTS ####

def crc32(x):
    return "%08X" % (0xffffffffL & zlib.crc32(x))

def sha1(x):
    return sha.sha(x).hexdigest().upper()

def compute_campaign_digests(test_campaign):
    dc = ""
    for ts in test_campaign:
        dts = ""
        for t in ts:
            dt = t.test.strip()
            t.crc = crc32(dt)
            dts += "\0"+dt
        ts.crc = crc32(dts)
        dc += "\0\x01"+dts
    test_campaign.crc = crc32(dc)
    test_campaign.sha = sha1(open(test_campaign.filename).read())


#### FILTER CAMPAIGN #####

def filter_tests_on_numbers(test_campaign, num):
    if num:
        for ts in test_campaign:
            ts.set = filter(lambda t: t.num in num, ts.set)
        test_campaign.campaign = filter(lambda ts: len(ts.set) > 0, test_campaign.campaign)

def filter_tests_keep_on_keywords(test_campaign, kw):
    def kw_match(lst, kw):
        for k in lst:
            if k in kw:
                return True
        return False
    
    if kw:
        for ts in test_campaign:
            ts.set = filter(lambda t: kw_match(t.keywords, kw), ts.set)

def filter_tests_remove_on_keywords(test_campaign, kw):
    def kw_match(lst, kw):
        for k in kw:
            if k not in lst:
                return False
        return True
    
    if kw:
        for ts in test_campaign:
            ts.set = filter(lambda t: not kw_match(t.keywords, kw), ts.set)


def remove_empty_testsets(test_campaign):
    test_campaign.campaign = filter(lambda ts: len(ts.set) > 0, test_campaign.campaign)


#### RUN CAMPAIGN #####

def run_campaign(test_campaign, get_interactive_session, verb=2):
    passed=failed=0
    if test_campaign.preexec:
        test_campaign.preexec_output = get_interactive_session(test_campaign.preexec.strip())[0]
    for testset in test_campaign:
        for t in testset:
            t.output,res = get_interactive_session(t.test.strip())
            the_res = False
            try:
                if res is None or res:
                    the_res= True
            except Exception,msg:
                t.output+="UTscapy: Error during result interpretation:\n"
                t.output+="".join(traceback.format_exception(sys.exc_type, sys.exc_value, sys.exc_traceback,))
            if the_res:
                t.res = True
                res = "passed"
                passed += 1
            else:
                t.res = False
                res = "failed"
                failed += 1
            t.result = res
            if verb > 1:
                print >>sys.stderr,"%(result)6s %(crc)s %(name)s" % t
    test_campaign.passed = passed
    test_campaign.failed = failed
    if verb:
        print >>sys.stderr,"Campaign CRC=%(crc)s  SHA=%(sha)s" % test_campaign
        print >>sys.stderr,"PASSED=%i FAILED=%i" % (passed, failed)


#### INFO LINES ####

def info_line(test_campaign):
    filename = test_campaign.filename
    if filename is None:
        return "Run %s by UTscapy" % time.ctime()
    else:
        return "Run %s from [%s] by UTscapy" % (time.ctime(), filename)

def html_info_line(test_campaign):
    filename = test_campaign.filename
    if filename is None:
        return """Run %s by <a href="http://www.secdev.org/projects/UTscapy/">UTscapy</a><br>""" % time.ctime()
    else:
        return """Run %s from [%s] by <a href="http://www.secdev.org/projects/UTscapy/">UTscapy</a><br>""" % (time.ctime(), filename)


#### CAMPAIGN TO something ####

def campaign_to_TEXT(test_campaign):
    output="%(title)s\n" % test_campaign
    output += "-- "+info_line(test_campaign)+"\n\n"
    output += "Passed=%(passed)i\nFailed=%(failed)i\n\n%(headcomments)s\n" % test_campaign
    
    for testset in test_campaign:
        output += "######\n## %(name)s\n######\n%(comments)s\n\n" % testset
        for t in testset:
            if t.expand:
                output += "###(%(num)03i)=[%(result)s] %(name)s\n%(comments)s\n%(output)s\n\n" % t

    return output
 
def campaign_to_ANSI(test_campaign):
    output="%(title)s\n" % test_campaign
    output += "-- "+info_line(test_campaign)+"\n\n"
    output += "Passed=%(passed)i\nFailed=%(failed)i\n\n%(headcomments)s\n" % test_campaign
    
    for testset in test_campaign:
        output += "######\n## %(name)s\n######\n%(comments)s\n\n" % testset
        for t in testset:
            if t.expand:
                output += "###(%(num)03i)=[%(result)s] %(name)s\n%(comments)s\n%(output)s\n\n" % t

    return output

def campaign_to_xUNIT(test_campaign):
    output='<?xml version="1.0" encoding="UTF-8" ?>\n<testsuite>\n'
    for testset in test_campaign:
        for t in testset:
            output += ' <testcase classname="%s"\n' % testset.name.encode("string_escape").replace('"',' ')
            output += '           name="%s"\n' % t.name.encode("string_escape").replace('"',' ')
            output += '           duration="0">\n' % t
            if not t.res:
                output += '<error><![CDATA[%(output)s]]></error>\n' % t
            output += "</testcase>\n"
    output += '</testsuite>'
    return output


def campaign_to_HTML(test_campaign, local=0):
    output = """<html>
<head>
<title>%(title)s</title>
<link rel="stylesheet" href="%%(UTscapy_css)s" type="text/css">
<script language="JavaScript" src="%%(UTscapy_js)s" type="text/javascript"></script>
</head>
<body>

<h1>%(title)s</h1>

<span class=button onClick="hide_all('tst')">Shrink All</span>
<span class=button onClick="show_all('tst')">Expand All</span>
<span class=button onClick="show_passed('tst')">Expand Passed</span>
<span class=button onClick="show_failed('tst')">Expand Failed</span>
<p>
""" % test_campaign

    if local:
        External_Files.UTscapy_js.write(os.path.dirname(test_campaign.output_file.name))
        External_Files.UTscapy_css.write(os.path.dirname(test_campaign.output_file.name))
        output %= External_Files.get_local_dict()
    else:
        output %= External_Files.get_URL_dict()

    if test_campaign.crc is not None and test_campaign.sha is not None:
        output += "CRC=<span class=crc>%(crc)s</span> SHA=<span class=crc>%(sha)s</span><br>" % test_campaign
    output += "<small><em>"+html_info_line(test_campaign)+"</em></small>"
    output += test_campaign.headcomments +  "\n<p>PASSED=%(passed)i FAILED=%(failed)i<p>\n\n" % test_campaign
    for ts in test_campaign:
        for t in ts:
            output += """<span class=button%(result)s onClick="goto_id('tst%(num)il')">%(num)03i</span>\n""" % t
    output += "\n\n"
    
    for testset in test_campaign:
        output += "<h2>" % testset
        if testset.crc is not None:
            output += "<span class=crc>%(crc)s</span> " % testset
        output += "%(name)s</h2>\n%(comments)s\n<ul>\n" % testset
        for t in testset:
            output += """<li class=%(result)s id="tst%(num)il">\n""" % t
            if t.expand == 2:
                output +="""
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
            output += """%(name)s\n<span class="comment %(result)s" id="tst%(num)i" """ % t
            if t.expand < 2:
                output += """ style="POSITION: absolute; VISIBILITY: hidden;" """
            output += """><br>%(comments)s
<pre>
%(output)s</pre></span>
""" % t
        output += "\n</ul>\n\n"

    output += "</body></html>"
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
    print >>sys.stderr,"""Usage: UTscapy [-m module] [-f {text|ansi|HTML|LaTeX}] [-o output_file] 
               [-t testfile] [-k keywords [-k ...]] [-K keywords [-K ...]]
               [-l] [-d|-D] [-F] [-q[q]] [-P preexecute_python_code]
               [-s /path/to/scpay]
-l\t\t: generate local files
-F\t\t: expand only failed tests
-d\t\t: dump campaign
-D\t\t: dump campaign and stop
-C\t\t: don't calculate CRC and SHA
-s\t\t: path to scapy.py
-q\t\t: quiet mode
-qq\t\t: [silent mode]
-n <testnum>\t: only tests whose numbers are given (eg. 1,3-7,12)
-m <module>\t: additional module to put in the namespace
-k <kw1>,<kw2>,...\t: include only tests with one of those keywords (can be used many times)
-K <kw1>,<kw2>,...\t: remove tests with one of those keywords (can be used many times)
-P <preexecute_python_code>
"""
    raise SystemExit


#### MAIN ####

def main(argv):
    import __builtin__

    # Parse arguments
    
    FORMAT = Format.ANSI
    TESTFILE = sys.stdin
    OUTPUTFILE = sys.stdout
    LOCAL = 0
    NUM=None
    KW_OK = []
    KW_KO = []
    DUMP = 0
    CRC = 1
    ONLYFAILED = 0
    VERB=2
    PREEXEC=""
    SCAPY="scapy"
    MODULES = []
    try:
        opts = getopt.getopt(argv, "o:t:f:hln:m:k:K:DdCFqP:s:")
        for opt,optarg in opts[0]:
            if opt == "-h":
                usage()
            elif opt == "-F":
                ONLYFAILED = 1
            elif opt == "-q":
                VERB -= 1
            elif opt == "-D":
                DUMP = 2
            elif opt == "-d":
                DUMP = 1
            elif opt == "-C":
                CRC = 0
            elif opt == "-s":
                SCAPY = optarg
            elif opt == "-P":
                PREEXEC += "\n"+optarg
            elif opt == "-f":
                try:
                    FORMAT = Format.from_string(optarg)
                except KeyError,msg:
                    raise getopt.GetoptError("Unknown output format %s" % msg)
            elif opt == "-t":
                TESTFILE = open(optarg)
            elif opt == "-o":
                OUTPUTFILE = open(optarg, "w")
            elif opt == "-l":
                LOCAL = 1
            elif opt == "-n":
                NUM = []
                for v in map( lambda x: x.strip(), optarg.split(",") ):
                    try:
                        NUM.append(int(v))
                    except ValueError:
                        v1,v2 = map(int, v.split("-"))
                        for vv in range(v1,v2+1):
                            NUM.append(vv)
            elif opt == "-m":
                MODULES.append(optarg)
            elif opt == "-k":
                KW_OK.append(optarg.split(","))
            elif opt == "-K":
                KW_KO.append(optarg.split(","))

        
        try:
            from scapy import all as scapy
        except ImportError,e:
            raise getopt.GetoptError("cannot import [%s]: %s" % (SCAPY,e))

        for m in MODULES:
            try:
                mod = import_module(m)
                __builtin__.__dict__.update(mod.__dict__)
            except ImportError,e:
                raise getopt.GetoptError("cannot import [%s]: %s" % (m,e))
                
    except getopt.GetoptError,msg:
        print >>sys.stderr,"ERROR:",msg
        raise SystemExit

    autorun_func = {
        Format.TEXT: scapy.autorun_get_text_interactive_session,
        Format.ANSI: scapy.autorun_get_ansi_interactive_session,
        Format.HTML: scapy.autorun_get_html_interactive_session,
        Format.LATEX: scapy.autorun_get_latex_interactive_session,
        Format.XUNIT: scapy.autorun_get_text_interactive_session,
        }

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
    run_campaign(test_campaign, autorun_func[FORMAT], verb=VERB)

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
        output = campaign_to_HTML(test_campaign, local=LOCAL)
    elif FORMAT == Format.LATEX:
        output = campaign_to_LATEX(test_campaign)
    elif FORMAT == Format.XUNIT:
        output = campaign_to_xUNIT(test_campaign)

    OUTPUTFILE.write(output)
    OUTPUTFILE.close()

if __name__ == "__main__":
    main(sys.argv[1:])
