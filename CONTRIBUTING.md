# How to contribute

Contributors are essential to Scapy (as they are to most open source
projects). Here is some advice to help you help the project!

## Project objectives

We try to keep Scapy as powerful as possible, to support as many
protocols and platforms as possible, to keep and make the code (and
the commit history) as clean as possible.

Since Scapy can be slow and memory consuming, we try to limit CPU and
memory usage, particularly in parts of the code often called.

## What to contribute?

You want to spend to time working on Scapy but have no (or little)
idea what to do? You can look for open issues
[labeled "contributions wanted"](https://github.com/secdev/scapy/labels/contributions%20wanted).

If you have any ideas of useful contributions that you cannot (or do
not want to) do yourself, open an issue and use the label
"contributions wanted".

Once you have chosen a contribution, open an issue to let other people
know you're working on it (or assign the existing issue to yourself)
and track your progress. You might want to ask whether you're working
in an appropriate direction, to avoid the frustration of seeing your
contribution rejected after a lot of work.

## Reporting issues

### Questions

It is OK so submit issues to ask questions (more than OK,
encouraged). There is a label "question" that you can use for that.

### Bugs

If you have installed Scapy through a package manager (from your Linux
or BSD system, from PyPI, etc.), please get and install the current
development code, and check that the bug still exists before
submitting an issue.

Please label your issues "bug".

If you're not sure whether a behavior is a bug or not, submit an issue
and ask, don't be shy!

### Enhancements / feature requests

If you want a feature in Scapy, but cannot implement it yourself or
want some hints on how to do that, open an issue with label
"enhancement".

Explain if possible the API you would like to have (e.g., give examples
of function calls, packet creations, etc.).

## Submitting pull requests

### Coding style & conventions

First, Scapy "legacy" code contains a lot of code that do not comply
with the following recommendations, but we try to comply with the some
guidelines for new code.

  - The code should be PEP-8 compliant; you can check your code with
    [pep8](https://pypi.python.org/pypi/pep8).
  - [Pylint](http://www.pylint.org/) can help you write good Python
    code (even if respecting Pylint rules is sometimes either too hard
    or even undesirable; human brain needed!).
  - [Google Python Style Guide](https://google.github.io/styleguide/pyguide.html)
    is a nice read!
  - Avoid creating unnecessary `list` objects, particularly if they
    can be huge (e.g., when possible, use `xrange()` instead of
    `range()`, `for line in fdesc` instead of `for line in
    fdesc.readlines()`; more generally prefer generators over lists).

### Tests

Please consider adding tests for your new features or that trigger the
bug you are fixing. This will prevent a regression from being
unnoticed.

### New protocols

New protocols can go either in `scapy/layers` or to
`scapy/contrib`. Protocols in `scapy/layers` should be usually found
on common networks, while protocols in `scapy/contrib` should be
uncommon or specific.

### Features

Protocol-related features should be implemented within the same module
as the protocol layers(s) (e.g., `traceroute()` is implemented in
`scapy/layers/inet.py`).

Other features may be implemented in a module (`scapy/modules`) or a
contribution (`scapy/contrib`).

### Core

If you contribute to Scapy's core (e.g., `scapy/base_classes.py`,
`scapy/packet.py`, etc.), please be very careful with performances and
memory footprint, as it is easy to write Python code that wastes
memory or CPU cycles.

As an example, Packet().__init__() is called each time a **layer** is
parsed from a string (during a network capture or a PCAP file
read). Adding inefficient code here will have a disastrous effect on
Scapy's performances.

### Code review

Maintainers tend to be picky, and you might feel frustrated that your
code (which is perfectly working in your use case) is not merged
faster.

Please don't be offended, and keep in mind that maintainers are
concerned about code maintainability and readability, commit history
(we use the history a lot, for example to find regressions or
understand why certain decisions have been made), performances,
integration in Scapy, API consistency (so that someone who knows how
to use Scapy will know how to use your code), etc.

**Thanks for reading, happy hacking!**
