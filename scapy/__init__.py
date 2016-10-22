## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

"""
Scapy: create, send, sniff, dissect and manipulate network packets.

Usable either from an interactive console or as a Python library.
http://www.secdev.org/projects/scapy
"""

import os
import re
import subprocess


_SCAPY_PKG_DIR = os.path.dirname(__file__)

def _version_from_git_describe():
    """
    Read the version from ``git describe``. It returns the latest tag with an
    optional suffix if the current directory is not exactly on the tag.

    Example::

        $ git describe --always
        v2.3.2-346-g164a52c075c8

    The tag prefix (``v``) and the git commit sha1 (``-g164a52c075c8``) are
    removed if present.

    If the current directory is not exactly on the tag, a ``.devN`` suffix is
    appended where N is the number of commits made after the last tag.

    Example::

        >>> _version_from_git_describe()
        '2.3.2.dev346'
    """
    p = subprocess.Popen(['git', 'describe', '--always'], cwd=_SCAPY_PKG_DIR,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    out, err = p.communicate()

    if p.returncode == 0:
        tag = out.strip()
        match = re.match(r'^v?(.+?)-(\d+)-g[a-f0-9]+$', tag)
        if match:
            # remove the 'v' prefix and add a '.devN' suffix
            return '%s.dev%s' % (match.group(1), match.group(2))
        else:
            # just remove the 'v' prefix
            return re.sub(r'^v', '', tag)
    else:
        raise subprocess.CalledProcessError(p.returncode, err)

def _version():
    version_file = os.path.join(_SCAPY_PKG_DIR, 'VERSION')
    try:
        tag = _version_from_git_describe()
        # successfully read the tag from git, write it in VERSION for
        # installation and/or archive generation.
        with open(version_file, 'w') as f:
            f.write(tag)
        return tag
    except:
        # failed to read the tag from git, try to read it from a VERSION file
        try:
            with open(version_file, 'r') as f:
                tag = f.read()
            return tag
        except:
            return 'unknown.version'

VERSION = _version()

if __name__ == "__main__":
    from scapy.main import interact
    interact()
