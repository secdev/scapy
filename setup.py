#! /usr/bin/env python

"""
Setuptools setup file for Scapy.
"""

import io
import os
import sys

if sys.version_info[0] <= 2:
    raise OSError("Scapy no longer supports Python 2 ! Please use Scapy 2.5.0")

try:
    from setuptools import setup
    from setuptools.command.sdist import sdist
except:
    raise ImportError("setuptools is required to install scapy !")


def get_long_description():
    """
    Extract description from README.md, for PyPI's usage
    """
    def process_ignore_tags(buffer):
        return "\n".join(
            x for x in buffer.split("\n") if "<!-- ignore_ppi -->" not in x
        )
    try:
        fpath = os.path.join(os.path.dirname(__file__), "README.md")
        with io.open(fpath, encoding="utf-8") as f:
            readme = f.read()
            desc = readme.partition("<!-- start_ppi_description -->")[2]
            desc = desc.partition("<!-- stop_ppi_description -->")[0]
            return process_ignore_tags(desc.strip())
    except IOError:
        return None


class SDist(sdist):
    """
    Modified sdist to create scapy/VERSION file
    """
    def make_release_tree(self, base_dir, *args, **kwargs):
        super(SDist, self).make_release_tree(base_dir, *args, **kwargs)
        # ensure there's a scapy/VERSION file
        fn = os.path.join(base_dir, 'scapy', 'VERSION')
        with open(fn, 'w') as f:
            f.write(__import__('scapy').VERSION)

setup(
    cmdclass={'sdist': SDist},
    long_description=get_long_description(),
    long_description_content_type='text/markdown',
)
