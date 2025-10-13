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
    from setuptools.command.build_py import build_py
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


# Note: why do we bother including a 'scapy/VERSION' file and doing our
# own versioning stuff, instead of using more standard methods?
# Because it's all garbage.

# If you remain fully standard, there's no way
# of adding the version dynamically, even less when using archives
# (currently, we're able to add the version anytime someone exports Scapy
# on github).

# If you use setuptools_scm, you'll be able to have the git tag set into
# the wheel (therefore the metadata), that you can then retrieve using
# importlib.metadata, BUT it breaks sdist (source packages), as those
# don't include metadata.


def _build_version(path):
    """
    This adds the scapy/VERSION file when creating a sdist and a wheel
    """
    fn = os.path.join(path, 'scapy', 'VERSION')
    with open(fn, 'w') as f:
        f.write(__import__('scapy').VERSION)


class SDist(sdist):
    """
    Modified sdist to create scapy/VERSION file
    """
    def make_release_tree(self, base_dir, *args, **kwargs):
        super(SDist, self).make_release_tree(base_dir, *args, **kwargs)
        # ensure there's a scapy/VERSION file
        _build_version(base_dir)


class BuildPy(build_py):
    """
    Modified build_py to create scapy/VERSION file
    """
    def build_package_data(self):
        super(BuildPy, self).build_package_data()
        # ensure there's a scapy/VERSION file
        _build_version(self.build_lib)

setup(
    cmdclass={'sdist': SDist, 'build_py': BuildPy},
    data_files=[('share/man/man1', ["doc/scapy.1"])],
    long_description=get_long_description(),
    long_description_content_type='text/markdown',
)
