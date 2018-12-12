#! /usr/bin/env python

"""
Distutils setup file for Scapy.
"""


from distutils import archive_util
from distutils import sysconfig
from distutils.core import setup
from distutils.command.sdist import sdist
import io
import os


EZIP_HEADER = """#! /bin/sh
PYTHONPATH=$0/%s exec python -m scapy
"""


def make_ezipfile(base_name, base_dir, verbose=0, dry_run=0, **kwargs):
    fname = archive_util.make_zipfile(base_name, base_dir, verbose, dry_run)
    ofname = fname + ".old"
    os.rename(fname, ofname)
    of = open(ofname)
    f = open(fname, "w")
    f.write(EZIP_HEADER % base_dir)
    while True:
        data = of.read(8192)
        if not data:
            break
        f.write(data)
    f.close()
    os.system("zip -A '%s'" % fname)
    of.close()
    os.unlink(ofname)
    os.chmod(fname, 0o755)
    return fname


archive_util.ARCHIVE_FORMATS["ezip"] = (
    make_ezipfile, [], 'Executable ZIP file')

def get_long_description():
    try:
        with io.open(os.path.join(os.path.dirname(__file__), "README.md"), encoding="utf-8") as f:
            return f.read().partition("<!--- stop_ppi_description -->")[0]
    except IOError:
        return None

SCRIPTS = ['bin/scapy', 'bin/UTscapy']
# On Windows we also need additional batch files to run the above scripts
if os.name == "nt":
    SCRIPTS += ['bin/scapy.bat', 'bin/UTscapy.bat']

setup(
    name='scapy',
    version=__import__('scapy').VERSION,
    packages=[
        'scapy',
        'scapy/arch',
        'scapy/arch/bpf',
        'scapy/arch/windows',
        'scapy/contrib',
        'scapy/contrib/automotive',
        'scapy/contrib/automotive/bmw',
        'scapy/contrib/automotive/gm',
        'scapy/contrib/automotive/obd',
        'scapy/contrib/automotive/obd/pid',
        'scapy/contrib/automotive/obd/iid',
        'scapy/layers',
        'scapy/layers/tls',
        'scapy/layers/tls/crypto',
        'scapy/modules',
        'scapy/modules/krack',
        'scapy/asn1',
        'scapy/tools',
    ],
    scripts=SCRIPTS,
    data_files=[('share/man/man1', ["doc/scapy.1"])],
    package_data={
        'scapy': ['VERSION'],
    },

    # Metadata
    author='Philippe BIONDI',
    author_email='phil(at)secdev.org',
    maintainer='Pierre LALET, Guillaume VALADON',
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
