#! /usr/bin/env python

"""
Distutils setup file for Scapy.
"""

try:
    from setuptools import setup, find_packages
except:
    raise ImportError("setuptools is required to install scapy !")
import io
import os


def get_long_description():
    """Extract description from README.md, for PyPI's usage"""
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


if __name__ == "__main__":
    setup(long_description=get_long_description())
