#! /usr/bin/env python


from distutils import archive_util
from distutils import sysconfig
from distutils.core import setup
from distutils.command.sdist import sdist
import os


EZIP_HEADER="""#! /bin/sh
PYTHONPATH=$0/%s exec python -m scapy
"""

def make_ezipfile(base_name, base_dir, verbose=0, dry_run=0):
    fname = archive_util.make_zipfile(base_name, base_dir, verbose, dry_run)
    ofname = fname+".old"
    os.rename(fname,ofname)
    of=open(ofname)
    f=open(fname,"w")
    f.write(EZIP_HEADER % base_dir)
    while True:
        data = of.read(8192)
        if not data:
            break
        f.write(data)
    f.close()
    of.close()
    os.unlink(ofname)
    os.chmod(fname,0755)
    return fname



archive_util.ARCHIVE_FORMATS["ezip"] = (make_ezipfile,[],'Executable ZIP file')


setup(
    name = 'scapy',
    version = '2.0.1', 
    packages=['scapy','scapy/arch', 'scapy/layers','scapy/asn1','scapy/tools','scapy/modules'],
    scripts = ['bin/scapy','bin/UTscapy'],
    data_files = [('share/man/man1', ["doc/scapy.1.gz"])],

    # Metadata
    author = 'Philippe BIONDI',
    author_email = 'phil(at)secdev.org',
    description = 'Scapy: interactive packet manipulation tool',
    license = 'GPLv2',
    url = 'http://www.secdev.org/projects/scapy'
    # keywords = '',
    # url = '',
)
