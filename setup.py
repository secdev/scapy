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
    try:
        fpath = os.path.join(os.path.dirname(__file__), "README.md")
        with io.open(fpath, encoding="utf-8") as f:
            readme = f.read()
            desc = readme.partition("<!-- start_ppi_description -->")[2]
            desc = desc.partition("<!-- stop_ppi_description -->")[0]
            return desc.strip()
    except IOError:
        return None


# https://packaging.python.org/guides/distributing-packages-using-setuptools/
setup(
    name='scapy',
    version=__import__('scapy').VERSION,
    packages=find_packages(),
    data_files=[('share/man/man1', ["doc/scapy.1"])],
    package_data={
        'scapy': ['VERSION'],
    },
    # Build starting scripts automatically
    entry_points={
        'console_scripts': [
            'scapy = scapy.main:interact',
            'UTscapy = scapy.tools.UTscapy:main'
        ]
    },
    python_requires='>=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*, <4',
    extras_require={
        'basic': ["ipython"],
        'complete': [
            'ipython>=7;  python_version>="3"',
            'ipython<6;  python_version<"3"',
            'pyx>=0.14; python_version>="3"',
            'pyx==0.12.1; python_version<"3"',
            'cryptography',
            'matplotlib'
        ]
    },

    # Metadata
    author='Philippe BIONDI',
    author_email='phil(at)secdev.org',
    maintainer='Pierre LALET, Gabriel POTTER, Guillaume VALADON',
    description='Scapy: interactive packet manipulation tool',
    long_description=get_long_description(),
    long_description_content_type='text/markdown',
    license='GPLv2',
    url='https://scapy.net',
    project_urls={
        'Documentation': 'https://scapy.readthedocs.io',
        'Source Code': 'https://github.com/secdev/scapy/',
    },
    download_url='https://github.com/secdev/scapy/tarball/master',
    keywords=["network"],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Science/Research",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Telecommunications Industry",
        "License :: OSI Approved :: GNU General Public License v2 (GPLv2)",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Topic :: Security",
        "Topic :: System :: Networking",
        "Topic :: System :: Networking :: Monitoring",
    ]
)
