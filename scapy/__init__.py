# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>

"""
Scapy: create, send, sniff, dissect and manipulate network packets.

Usable either from an interactive console or as a Python library.
https://scapy.net
"""

import datetime
import os
import re
import subprocess

__all__ = [
    "VERSION",
    "__version__",
]

_SCAPY_PKG_DIR = os.path.dirname(__file__)


def _parse_tag(tag):
    # type: (str) -> str
    """
    Parse a tag from ``git describe`` into a version.

    Example::

        v2.3.2-346-g164a52c075c8 -> '2.3.2.dev346'
    """
    match = re.match('^v?(.+?)-(\\d+)-g[a-f0-9]+$', tag)
    if match:
        # remove the 'v' prefix and add a '.devN' suffix
        return '%s.dev%s' % (match.group(1), match.group(2))
    else:
        match = re.match('^v?([\\d\\.]+(rc\\d+)?)$', tag)
        if match:
            # tagged release version
            return '%s' % (match.group(1))
        else:
            raise ValueError('tag has invalid format')


def _version_from_git_archive():
    # type: () -> str
    """
    Rely on git archive "export-subst" git attribute.
    See 'man gitattributes' for more details.
    Note: describe is only supported with git >= 2.32.0,
    and the `tags=true` option with git >= 2.35.0 but we
    use it to workaround GH#3121.
    """
    git_archive_id = '$Format:%ct %(describe:tags=true)$'.split()
    tstamp = git_archive_id[0]
    if len(git_archive_id) > 1:
        tag = git_archive_id[1]
    else:
        # project is run in CI and has another %(describe)
        tag = ""

    if "Format" in tstamp:
        raise ValueError('not a git archive')

    if "describe" in tag:
        # git is too old!
        tag = ""
    if tag:
        # archived revision is tagged, use the tag
        return _parse_tag(tag)
    elif tstamp:
        # archived revision is not tagged, use the commit date
        d = datetime.datetime.fromtimestamp(int(tstamp), datetime.timezone.utc)
        return d.strftime('%Y.%m.%d')

    raise ValueError("invalid git archive format")


def _version_from_git_describe():
    # type: () -> str
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

    :raises CalledProcessError: if git is unavailable
    :return: Scapy's latest tag
    """
    if not os.path.isdir(os.path.join(os.path.dirname(_SCAPY_PKG_DIR), '.git')):  # noqa: E501
        raise ValueError('not in scapy git repo')

    def _git(cmd):
        # type: (str) -> str
        process = subprocess.Popen(
            cmd.split(),
            cwd=_SCAPY_PKG_DIR,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        out, err = process.communicate()
        if process.returncode == 0:
            return out.decode().strip()
        else:
            raise subprocess.CalledProcessError(process.returncode, err)

    tag = _git("git describe --tags --always --long")
    if not tag.startswith("v"):
        # Upstream was not fetched
        commit = _git("git rev-list --tags --max-count=1")
        tag = _git("git describe --tags --always --long %s" % commit)
    return _parse_tag(tag)


def _version():
    # type: () -> str
    """Returns the Scapy version from multiple methods

    :return: the Scapy version
    """
    # Method 0: from external packaging
    try:
        # possibly forced by external packaging
        return os.environ['SCAPY_VERSION']
    except KeyError:
        pass

    # Method 1: from the VERSION file, included in sdist and wheels
    version_file = os.path.join(_SCAPY_PKG_DIR, 'VERSION')
    try:
        # file generated when running sdist
        with open(version_file, 'r') as fdsec:
            tag = fdsec.read()
        return tag
    except (FileNotFoundError, NotADirectoryError):
        pass

    # Method 2: from the archive tag, exported when using git archives
    try:
        return _version_from_git_archive()
    except ValueError:
        pass

    # Method 3: from git itself, used when Scapy was cloned
    try:
        return _version_from_git_describe()
    except Exception:
        pass

    # Fallback
    try:
        # last resort, use the modification date of __init__.py
        d = datetime.datetime.fromtimestamp(
            os.path.getmtime(__file__), datetime.timezone.utc
        )
        return d.strftime('%Y.%m.%d')
    except Exception:
        pass

    # all hope is lost
    return '0.0.0'


VERSION = __version__ = _version()

_tmp = re.search(r"([0-9]|\.[0-9])+", VERSION)
VERSION_MAIN = _tmp.group() if _tmp is not None else VERSION

if __name__ == "__main__":
    from scapy.main import interact
    interact()
