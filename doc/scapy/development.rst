*****************
Scapy development
*****************

Project organization
====================

Scapy development uses the Git version control system. Scapy's
reference repository is at https://github.com/secdev/scapy/.

Project management is done with `Github
<https://github.com/secdev/scapy/>`_.  It provides a freely editable
`Wiki <https://github.com/secdev/scapy/wiki/>`_ (please contribute!)
that can reference tickets, changesets, files from the project. It
also provides a ticket management service that is used to avoid
forgetting patches or bugs.

How to contribute
=================

* Found a bug in Scapy? `Add a ticket <https://github.com/secdev/scapy/issues/new>`_.
* Improve this documentation.
* Program a new layer and share it on the mailing list, or create a pull request.
* Contribute new `regression tests <https://github.com/secdev/scapy/wiki/Contrib:-RegressionTests>`_.
* Upload packet samples for new protocols on the `packet samples page
  <https://github.com/secdev/scapy/wiki/Contrib:-PacketSamples>`_.


Improve the documentation
=========================

The documentation can be improved in several ways by:

* Adding docstrings to the source code.
* Adding usage examples to the documentation.

Adding Docstrings
-----------------
The Scapy source code has few explanations of what a function is doing. A docstring, by adding explanation and
expected input and output parameters, helps saving time for both the layer developers and the users looking for
advanced features.

An example of docstring from the ``scapy.fields.FlagsField`` class: ::

  class FlagsField(BitField):
    """ Handle Flag type field

     Make sure all your flags have a label

     Example:
         >>> from scapy.packet import Packet
         >>> class FlagsTest(Packet):
                 fields_desc = [FlagsField("flags", 0, 8, ["f0", "f1", "f2", "f3", "f4", "f5", "f6", "f7"])]
         >>> FlagsTest(flags=9).show2()
         ###[ FlagsTest ]###
           flags     = f0+f3
         >>> FlagsTest(flags=0).show2().strip()
         ###[ FlagsTest ]###
           flags     =

     :param name: field's name
     :param default: default value for the field
     :param size: number of bits in the field
     :param names: (list or dict) label for each flag, Least Significant Bit tag's name is written first
     """

It will contain a short one-line description of the class followed by some indications about its usage.
You can add a usage example if it makes sense using the `doctest <https://docs.python.org/2.7/library/doctest.html>`_ format.
Finally, the classic python signature can be added following the `sphinx documentation  <http://www.sphinx-doc.org/en/stable/domains.html#python-signatures>`_.

This task works in pair with writing non regression unit tests.

Documentation
-------------
A way to improve the documentation content is by keeping it up to date with the latest version of Scapy. You can also help by adding usage examples of your own or directly gathered from existing online Scapy presentations.

Testing with UTScapy
====================

What is UTScapy?
----------------

UTScapy is a small Python program that reads a campaign of tests, runs the campaign with Scapy and generates a report indicating test status. The report may be in one of four formats, text, ansi, HTML or LaTeX.

Three basic test containers exist with UTScapy, a unit test, a test set and a test campaign. A unit test is a list of Scapy commands that will be run by Scapy or a derived work of Scapy. Evaluation of the last command in the unit test will determine the end result of the individual unit test. A test set is a group of unit tests with some association. A test campaign consists of one or more test sets. Test sets and unit tests can be given keywords to form logical groupings. When running a campaign, tests may be selected by keyword. This allows the user to run tests within the desired grouping.

For each unit test, test set and campaign, a CRC32 of the test is calculated and displayed as a signature of that test. This test signature is sufficient to determine that the actual test run was the one expected and not one that has been modified. In case your dealing with evil people that try to modify or corrupt the file without changing the CRC32, a global SHA1 is computed on the whole file.

Syntax of a Test Campaign
-------------------------

Table 1 shows the syntax indicators that UTScapy is looking for. The syntax specifier must appear as the first character of each line of the text file that defines the test. Text descriptions that follow the syntax specifier are arguments interpreted by UTScapy. Lines that appear without a leading syntax specifier will be treated as Python commands, provided they appear in the context of a unit test. Lines without a syntax specifier that appear outside the correct context will be rejected by UTScapy and a warning will be issued. 

================   =================
Syntax Specifier   Definition
================   =================
‘%’                Give the test campaign's name.
‘+’                Announce a new test set.
‘=’                Announce a new unit test.
‘~’                Announce keywords for the current unit test.
‘*’                Denotes a comment that will be included in the report.
‘#’                Testcase annotations that are discarded by the interpreter.
================   =================

Table 1 - UTScapy Syntax Specifiers

Comments placed in the test report have a context. Each comment will be associated with the last defined test container - be it an individual unit test, a test set or a test campaign. Multiple comments associated with a particular container will be concatenated together and will appear in the report directly after the test container announcement. General comments for a test file should appear before announcing a test campaign. For comments to be associated with a test campaign, they must appear after the declaration of the test campaign but before any test set or unit test. Comments for a test set should appear before the definition of the set’s first unit test.

The generic format for a test campaign is shown in the following table::

    % Test Campaign Name
    * Comment describing this campaign

    
    + Test Set 1
    * comments for test set 1
    
    = Unit Test 1
    ~ keywords
    * Comments for unit test 1
    # Python statements follow
    a = 1
    print a
    a == 1


Python statements are identified by the lack of a defined UTScapy syntax specifier. The Python statements are fed directly to the Python interpreter as if one is operating within the interactive Scapy shell (``interact``). Looping, iteration and conditionals are permissible but must be terminated by a blank line. A test set may be comprised of multiple unit tests and multiple test sets may be defined for each campaign. It is even possible to have multiple test campaigns in a particular test definition file. The use of keywords allows testing of subsets of the entire campaign. For example, during the development of a test campaign, the user may wish to mark new tests under development with the keyword “debug”. Once the tests run successfully to their desired conclusion, the keyword “debug” could be removed. Keywords such as “regression” or “limited” could be used as well.

It is important to note that UTScapy uses the truth value from the last Python statement as the indicator as to whether a test passed or failed. Multiple logical tests may appear on the last line. If the result is 0 or False, the test fails. Otherwise, the test passes. Use of an assert() statement can force evaluation of intermediate values if needed.

The syntax for UTScapy is shown in Table 3 - UTScapy command line syntax::

    [root@localhost scapy]# ./UTscapy.py –h
    Usage: UTscapy [-m module] [-f {text|ansi|HTML|LaTeX}] [-o output_file]
                   [-t testfile] [-k keywords [-k ...]] [-K keywords [-K ...]]
                   [-l] [-d|-D] [-F] [-q[q]]
    -l              : generate local files
    -F              : expand only failed tests
    -d              : dump campaign
    -D              : dump campaign and stop
    -C              : don't calculate CRC and SHA
    -q              : quiet mode
    -qq             : [silent mode]
    -n <testnum>    : only tests whose numbers are given (eg. 1,3-7,12)
    -m <module>     : additional module to put in the namespace
    -k <kw1>,<kw2>,...      : include only tests with one of those keywords (can be used many times)
    -K <kw1>,<kw2>,...      : remove tests with one of those keywords (can be used many times)

Table 3 - UTScapy command line syntax

All arguments are optional. Arguments that have no associated argument value may be strung together (i.e. ``–lqF``). If no testfile is specified, the test definition comes from <STDIN>. Similarly, if no output file is specified it is directed to <STDOUT>. The default output format is “ansi”. Table 4 lists the arguments, the associated argument value and their meaning to UTScapy.

==========  ==============  =============================================================================
Argument    Argument Value  Meaning to UTScapy
==========  ==============  =============================================================================
-t          testfile        Input test file defining test campaign (default = <STDIN>)
-o          output_file     File for output of test campaign results (default = <STDOUT>)
-f          test            ansi, HTML, LaTeX, Format out output report (default = ansi)
-l                          Generate report associated files locally. For HTML, generates JavaScript 
                            and the style sheet
-F                          Failed test cases will be initially expanded by default in HTML output
-d                          Print a terse listing of the campaign before executing the campaign
-D                          Print a terse listing of the campaign and stop. Do not execute campaign
-C                          Do not calculate test signatures
-q                          Do not update test progress to the screen as tests are executed
-qq                         Silent mode
-n          testnum         Execute only those tests listed by number. Test numbers may be
                            retrieved using –d or –D. Tests may be listed as a comma
                            separated list and may include ranges (e.g. 1, 3-7, 12)
-m          module          Load module before executing tests. Useful in testing derived works of Scapy.
                            Note: Derived works that are intended to execute as "__main__" will not be
                            invoked by UTScapy as “__main__”.
-k          kw1, kw2, ...   Include only tests with keyword “kw1”. Multiple keywords may be specified.
-K          kw1, kw2, ...   Exclude tests with keyword “kw1”. Multiple keywords may be specified.  
==========  ==============  =============================================================================

Table 4 - UTScapy parameters

Table 5 shows a simple test campaign with multiple tests set definitions. Additionally, keywords are specified that allow a limited number of test cases to be executed. Notice the use of the ``assert()`` statement in test 3 and 5 used to check intermediate results. Tests 2 and 5 will fail by design.

:: 

    % Example Test Campaign
    
    # Comment describing this campaign
    #
    # To run this campaign, try:
    #   ./UTscapy.py -t example_campaign.txt -f html -o example_campaign.html -F
    #
    
    * This comment is associated with the test campaign and will appear 
    * in the produced output.
    
    + Test Set 1
    
    = Unit Test 1
    ~ test_set_1 simple
    a = 1
    print a
    
    = Unit test 2
    ~ test_set_1 simple
    * this test will fail
    b = 2
    a == b
    
    = Unit test 3
    ~ test_set_1 harder
    a = 1
    b = 2
    c = "hello"
    assert (a != b)
    c == "hello"
    
    + Test Set 2
    
    = Unit Test 4
    ~ test_set_2 harder
    b = 2
    d = b
    d is b
    
    = Unit Test 5
    ~ test_set_2 harder hardest
    a = 2
    b = 3
    d = 4
    e = (a * b)**d
    # The following statement evaluates to False but is not last; continue
    e == 6
    # assert evaluates to False; stop test and fail
    assert (e == 7)
    e == 1296
    
    = Unit Test 6
    ~ test_set_2 hardest
    print e
    e == 1296

To see an example that is targeted to Scapy, go to http://www.secdev.org/projects/UTscapy. Cut and paste the example at the bottom of the page to the file ``demo_campaign.txt`` and run UTScapy against it::

./test/run_tests -t demo_campaign.txt -f html -o demo_campaign.html -F -l

Examine the output generated in file ``demo_campaign.html``.

Using tox to test Scapy
-----------------------

The ``tox`` command simplifies testing Scapy. It will automatically create
virtual environments and install the mandatory Python modules.

For example, on a fresh Debian installation, the following command will start
all Scapy unit tests automatically without any external dependency::

 tox -- -K vcan_socket -K tcpdump -K tshark -K nmap -K manufdb -K crypto

.. note:: This will trigger the unit tests on all available Python versions
  unless you specify a `-e` option. See below

For your convenience, and for package maintainers, we provide a util that
run tox on only a single (default Python) environment, again with no external
dependencies::

 ./test/run_tests

VIM syntax highlighting for .uts files
--------------------------------------

Copy all files from ``scapy/doc/syntax/vim_uts_syntax/ftdetect`` and ``scapy/doc/syntax/vim_uts_syntax/syntax`` into ``~/.vim/`` and preserve the folder structure.

If ftdetect/filetype.vim already exists, you might need to modify this file manually.

These commands will do the installation::

 cp -i -v ftdetect/filetype.vim $HOME/.vim/ftdetect/filetype.vim
 cp -i -v ftdetect/uts.vim $HOME/.vim/ftdetect/uts.vim
 cp -i -v syntax/uts.vim $HOME/.vim/syntax/uts.vim

Alternatively, a install script in ``scapy/doc/syntax/vim_uts_syntax/`` does the installation automatically.


Releasing Scapy
===============

Under the hood, a Scapy release is represented as a signed git tag. Prior to
signing a commit, the maintainer that wishes to create a release must:

* check that the corresponding Travis and AppVeyor tests pass
* run ``./run_scapy`` locally
* run ``tox``
* run unit tests on BSD using the Vagrant setup from ``scapy/doc/vagrant_ci/``

Taking v2.4.3 as an example, the following commands can be used to sign and
publish the release::

 git tag -s v2.4.3 -m "Release 2.4.3"
 git tag v2.4.3 -v
 git push --tags

Release Candidates (RC) could also be done. For example, the first RC will be
tagged v2.4.3rc1 and the message ``2.4.3 Release Candidate #1``.

Prior to uploading the release to PyPi, the ``author_email`` in ``setup.py``
must be changed to the address of the maintainer performing the release. The
following commands can then be used::

 python3 setup.py sdist
 twine check dist/scapy-2.4.3.tar.gz
 twine upload dist/scapy-2.4.3.tar.gz
