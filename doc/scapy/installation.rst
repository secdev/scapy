.. highlight:: sh

*************************
Download and Installation
*************************

Overview
========

 0. Install *Python 2.5*.
 1. Download and install *Scapy*.
 2. (For non-Linux platforms): Install *libpcap and libdnet* and their Python wrappers.
 3. (Optional): Install *additional software* for special features.
 4. Run Scapy with root priviledges.
 
Each of these steps can be done in a different way dependent on your platform and on the version of Scapy you want to use. 

At the moment, there are two different versions of Scapy:

* **Scapy v1.x**. It consists of only one file and works on Python 2.4, so it might be easier to install.
  Moreover, your OS may already have a specially prepared packages or ports for it. Last version is v1.2.2.
* **Scapy v2.x**. The current development version adds several features (e.g. IPv6). It consists of several
  files  packaged in the standard distutils way. Scapy v2 needs Python 2.5.

.. note::

   In Scapy v2 use ``from scapy.all import *`` instead of ``from scapy import *``.


Installing Scapy v2.x
=====================

The following steps describe how to install (or update) Scapy itself.
Dependent on your platform, some additional libraries might have to be installed to make it actually work. 
So please also have a look at the platform specific chapters on how to install those requirements.

.. note::

   The following steps apply to Unix-like operating systems (Linux, BSD, Mac OS X). 
   For Windows, see the special chapter below.

Make sure you have Python installed before you go on.

Latest release
--------------

Download the `latest version <http://scapy.net>`_ to a temporary directory and install it in the standard `distutils <http://docs.python.org/inst/inst.html>`_ way::

$ cd /tmp
$ wget scapy.net 
$ unzip scapy-latest.zip
$ cd scapy-2.*
$ sudo python setup.py install
 
Alternatively, you can execute the zip file::

$ chmod +x scapy-latest.zip
$ sudo ./scapy-latest.zip

or::

$ sudo sh scapy-latest.zip

or::

$ mv scapy-latest.zip /usr/local/bin/scapy
$ sudo scapy

.. note::

   To make a zip executable, some bytes have been added before the zip header.
   Most zip programs handle this, but not all. If your zip program complains
   about the zip file to be corrupted, either change it, or download a 
   non-executable zip at http://hg.secdev.org/scapy/archive/tip.zip

 
Current development version
----------------------------

.. index::
   single: Mercurial, repository

If you always want the latest version with all new features and bugfixes, use Scapy's Mercurial repository:

1. Install the `Mercurial <http://www.selenic.com/mercurial/>`_ version control system. For example, on Debian/Ubuntu use::

      $ sudo apt-get install mercurial

   or on OpenBSD:: 
    
      $ pkg_add mercurial

2. Check out a clone of Scapy's repository::
    
   $ hg clone http://hg.secdev.org/scapy
    
3. Install Scapy in the standard distutils way:: 
    
   $ cd scapy
   $ sudo python setup.py install
    
Then you can always update to the latest version::

$ hg pull
$ hg update       
$ sudo python setup.py install
 
For more information about Mercurial, have a look at the `Mercurial book <http://hgbook.red-bean.com/>`_. 


Installing Scapy v1.2
=====================

As Scapy v1 consists only of one single Python file, installation is easy:
Just download the last version and run it with your Python interpreter::

 $ wget http://hg.secdev.org/scapy/raw-file/v1.2.0.2/scapy.py
 $ sudo python scapy.py

.. index::
   single: scapy-bpf

On BSD systems, you can also try the latest version of `Scapy-bpf <http://hg.natisbad.org/scapy-bpf/raw-file/tip/scapy.py>`_ (`development repository <http://hg.natisbad.org/scapy-bpf/>`_). It doesn't need libpcap or libdnet.


Optional software for special features
======================================

For some special features you have to install more software. 
Platform-specific instructions on how to install those packages can be found in the next chapter.
Here are the topics involved and some examples that you can use to try if your installation was successful.

.. index::
   single: plot()

* Plotting. ``plot()`` needs `Gnuplot-py <http://gnuplot-py.sourceforge.net/>`_ which needs `GnuPlot <http://www.gnuplot.info/>`_ and `NumPy <http://numpy.scipy.org/>`_.
 
  .. code-block:: python
   
     >>> p=sniff(count=50)
     >>> p.plot(lambda x:len(x))
 
* 2D graphics. ``psdump()`` and ``pdfdump()`` need `PyX <http://pyx.sourceforge.net/>`_ which in turn needs a `LaTeX distribution <http://www.tug.org/texlive/>`_. For viewing the PDF and PS files interactively, you also need `Adobe Reader <http://www.adobe.com/products/reader/>`_ (``acroread``) and `gv <http://wwwthep.physik.uni-mainz.de/~plass/gv/>`_ (``gv``). 
  
  .. code-block:: python
   
     >>> p=IP()/ICMP()
     >>> p.pdfdump("test.pdf") 
 
* Graphs. ``conversations()`` needs `Grapviz <http://www.graphviz.org/>`_ and `ImageMagick <http://www.imagemagick.org/>`_.
 
  .. code-block:: python

     >>> p=readpcap("myfile.pcap")
     >>> p.conversations(type="jpg", target="> test.jpg")
 
* 3D graphics. ``trace3D()`` needs `VPython <http://www.vpython.org/>`_.
 
  .. code-block:: python

     >>> a,u=traceroute(["www.python.org", "google.com","slashdot.org"])
     >>> a.trace3D()

.. index::
   single: WEP, unwep()

* WEP decryption. ``unwep()`` needs `PyCrypto <http://www.dlitz.net/software/pycrypto/>`_. Example using a `Weplap test file <http://weplab.sourceforge.net/caps/weplab-64bit-AA-managed.pcap>`_:

  .. code-block:: python

     >>> enc=rdpcap("weplab-64bit-AA-managed.pcap")
     >>> enc.show()
     >>> enc[0]
      >>> conf.wepkey="AA\x00\x00\x00"
      >>> dec=Dot11PacketList(enc).toEthernet()
      >>> dec.show()
      >>> dec[0]
 
* Fingerprinting. ``nmap_fp()`` needs `Nmap <http://nmap.org>`_. You need an `old version <http://nmap.org/dist-old/>`_ (before v4.23) that still supports first generation fingerprinting.

  .. code-block:: python 
  
     >>> load_module("nmap")
     >>> nmap_fp("192.168.0.1")
     Begin emission:
     Finished to send 8 packets.
     Received 19 packets, got 4 answers, remaining 4 packets
     (0.88749999999999996, ['Draytek Vigor 2000 ISDN router'])

.. index::
   single: VOIP
 
* VOIP. ``voip_play()`` needs `SoX <http://sox.sourceforge.net/>`_.
 

Platform-specific instructions
==============================

Linux native
------------

Scapy can run natively on Linux, without libdnet and libpcap.

* Install `Python 2.5 <http://www.python.org>`_.
* Install `tcpdump <http://www.tcpdump.org>`_ and make sure it is in the $PATH. (It's only used to compile BPF filters (``-ddd option``))
* Make sure your kernel has Packet sockets selected (``CONFIG_PACKET``)
* If your kernel is < 2.6, make sure that Socket filtering is selected ``CONFIG_FILTER``) 

Debian/Ubuntu
-------------

Just use the standard packages::

$ sudo apt-get install tcpdump graphviz imagemagick python-gnuplot python-crypto python-pyx 

Fedora
------

Here's how to install Scapy on Fedora 9:

.. code-block:: text

    # yum install mercurial python-devel
    # cd /tmp
    # hg clone http://hg.secdev.org/scapy
    # cd scapy
    # python setup.py install
    
Some optional packages:

.. code-block:: text

    # yum install graphviz python-crypto sox PyX gnuplot numpy
    # cd /tmp
    # wget http://heanet.dl.sourceforge.net/sourceforge/gnuplot-py/gnuplot-py-1.8.tar.gz
    # tar xvfz gnuplot-py-1.8.tar.gz
    # cd gnuplot-py-1.8
    # python setup.py install


Mac OS X
--------

Here's how to install Scapy on Mac OS 10.4 (Tiger) or 10.5 (Leopard).

Set up a development environment
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

1. Install X11. 
   On the Mac OS X DVD, it is located in the "Optional Installs.mpkg" package.
 
2. Install SDK.
   On the Mac OS X DVD, it is located in the "Xcode Tools/Packages" directory.

3. Install Python 2.5 from Python.org.
   Using Apple's Python version will lead to some problems.
   Get it from http://www.python.org/ftp/python/2.5.2/python-2.5.2-macosx.dmg

Install using MacPorts
^^^^^^^^^^^^^^^^^^^^^^

3. Install MacPorts
   Download the dmg from macports.org and install it.
     
4. Update MacPorts::

   $ sudo port -d selfupdate

5. Install Scapy::

   $ sudo port install scapy

You can then update to the latest version as shown in the generic installation above. 

Install from original sources
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Install libdnet and its Python wrapper::

 $ wget http://libdnet.googlecode.com/files/libdnet-1.12.tgz
 $ tar xfz libdnet-1.12.tgz 
 $ ./configure
 $ make
 $ sudo make install
 $ cd python
 $ python2.5 setup.py install

Install libpcap and its Python wrapper::

 $ wget http://dfn.dl.sourceforge.net/sourceforge/pylibpcap/pylibpcap-0.6.2.tar.gz
 $ tar xfz pylibpcap-0.6.2.tar.gz
 $ cd pylibpcap-0.6.2
 $ python2.5 setup.py install

Optionally: Install readline::

 $ python `python -c "import pimp; print pimp.__file__"` -i readline

OpenBSD
-------

Here's how to install Scapy on OpenBSD 4.3.

.. code-block:: text

 # export PKG_PATH=ftp://ftp.openbsd.org/pub/OpenBSD/4.3/packages/i386/
 # pkg_add py-libpcap py-libdnet mercurial
 # ln -sf /usr/local/bin/python2.5 /usr/local/bin/python
 # cd /tmp
 # hg clone http://hg.secdev.org/scapy
 # cd scapy
 # python setup.py install


Optional packages
^^^^^^^^^^^^^^^^^

py-crypto

.. code-block:: text

 # pkg_add py-crypto

gnuplot and its Python binding: 

.. code-block:: text

 # pkg_add gnuplot py-gnuplot

Graphviz (large download, will install several GNOME libraries)

.. code-block:: text

 # pkg_add graphviz

   
ImageMagick (takes long to compile)

.. code-block:: text

 # cd /tmp
 # ftp ftp://ftp.openbsd.org/pub/OpenBSD/4.3/ports.tar.gz 
 # cd /usr
 # tar xvfz /tmp/ports.tar.gz 
 # cd /usr/ports/graphics/ImageMagick/
 # make install

PyX (very large download, will install texlive etc.)

.. code-block:: text

 # pkg_add py-pyx

/etc/ethertypes

.. code-block:: text

 # wget http://www.secdev.org/projects/scapy/files/ethertypes -O /etc/ethertypes

python-bz2 (for UTscapy)

.. code-block:: text

 # pkg_add python-bz2    

.. _windows_installation:

Windows
-------

.. sectionauthor:: Dirk Loss <mail at dirk-loss.de>

Scapy is primarily being developed for Unix-like systems and works best on those platforms. But the latest version of Scapy supports Windows out-of-the-box. So you can use nearly all of Scapy's features on your Windows machine as well.

.. note::
   If you update from Scapy-win v1.2.0.2 to Scapy v2 remember to use ``from scapy.all import *`` instead of ``from scapy import *``.

.. image:: graphics/scapy-win-screenshot1.png
   :scale: 80
   :align: center

You need the following software packages in order to install Scapy on Windows:

  * `Python <http://www.python.org>`_: `python-2.5.4.msi <http://www.python.org/ftp/python/2.5.4/python-2.5.4.msi>`_. `python-2.6.3.msi <http://www.python.org/ftp/python/2.6.3/python-2.6.3.msi>`_. After installation, add the Python installation directory and its \Scripts subdirectory to your PATH. Depending on your Python version, the defaults would be ``C:\Python25`` and ``C:\Python25\Scripts`` or ``C:\Python26`` and ``C:\Python26\Scripts`` respectively.
  * `Scapy <http://www.secdev.org/projects/scapy/>`_: `latest development version <http://hg.secdev.org/scapy/archive/tip.zip>`_ from the `Mercurial repository <http://hg.secdev.org/scapy>`_. Unzip the archive, open a command prompt in that directory and run "python setup.py install". 
  * `pywin32 <http://python.net/crew/mhammond/win32/Downloads.html>`_: `pywin32-214.win32-py2.5.exe <http://surfnet.dl.sourceforge.net/sourceforge/pywin32/pywin32-214.win32-py2.5.exe>`_ `pywin32-214.win32-py2.6.exe <http://downloads.sourceforge.net/project/pywin32/pywin32/Build%20214/pywin32-214.win32-py2.6.exe>`_
  * `WinPcap <http://www.winpcap.org/>`_: `WinPcap_4_1_1.exe <http://www.winpcap.org/install/bin/WinPcap_4_1_1.exe>`_. You might want to choose "[x] Automatically start the WinPcap driver at boot time", so that non-privileged users can sniff, especially under Vista and Windows 7. If you want to use the ethernet vendor database to resolve MAC addresses or use the ``wireshark()`` command, download `Wireshark <http://www.wireshark.org/>`_ which already includes WinPcap. 
  * `pypcap <http://code.google.com/p/pypcap/>`_: `pcap-1.1-scapy-20090720.win32-py25.exe <http://www.secdev.org/projects/scapy/files/pcap-1.1-scapy-20090720.win32-py2.5.exe>`_ `pcap-1.1-scapy-20090720.win32-py2.6.exe <http://www.secdev.org/projects/scapy/files/pcap-1.1-scapy-20090720.win32-py2.6.exe>`_. This is a *special version for Scapy*, as the original leads to some timing problems. Now works on Vista and Windows 7, too. Under Vista/Win7 please right-click on the installer and choose "Run as administrator".
  * `libdnet <http://code.google.com/p/libdnet/>`_:  `dnet-1.12.win32-py2.5.exe <http://libdnet.googlecode.com/files/dnet-1.12.win32-py2.5.exe>`_ `dnet-1.12.win32-py2.6.exe <http://www.secdev.org/projects/scapy/files/dnet-1.12.win32-py2.6.exe>`_. Under Vista/Win7 please right-click on the installer and choose "Run as administrator"
  * `pyreadline <http://ipython.scipy.org/moin/PyReadline/Intro>`_: `pyreadline-1.5-win32-setup.exe <http://ipython.scipy.org/dist/pyreadline-1.5-win32-setup.exe>`_

Just download the files and run the setup program. Choosing the default installation options should be safe.

For your convenience direct links are given to the versions I used (for Python 2.5 and Python 2.6). If these links do not work or if you are using a different Python version, just visit the homepage of the respective package and look for a Windows binary. As a last resort, search the web for the filename.

After all packages are installed, open a command prompt (cmd.exe) and run Scapy by typing ``scapy``. If you have set the PATH correctly, this will find a little batch file in your ``C:\Python26\Scripts`` directory and instruct the Python interpreter to load Scapy.

If really nothing seems to work, consider skipping the Windows version and using Scapy from a Linux Live CD -- either in a virtual machine on your Windows host or by booting from CDROM: An older version of Scapy is already included in grml and BackTrack for example. While using the Live CD you can easily upgrade to the lastest Scapy version by typing ``cd /tmp && wget scapy.net``.

Optional packages
^^^^^^^^^^^^^^^^^

Plotting (``plot``)

 * `GnuPlot <http://www.gnuplot.info/>`_: `gp420win32.zip <http://downloads.sourceforge.net/gnuplot/gp420win32.zip>`_. Extract the zip file (e.g. to ``c:\gnuplot``) and add the ``gnuplot\bin`` directory to your PATH.
 * `NumPy <http://numpy.scipy.org/>`_: `numpy-1.3.0-win32-superpack-python2.5.exe <http://downloads.sourceforge.net/project/numpy/NumPy/1.3.0/numpy-1.3.0-win32-superpack-python2.5.exe>`_ `numpy-1.3.0-win32-superpack-python2.6.exe <http://downloads.sourceforge.net/project/numpy/NumPy/1.3.0/numpy-1.3.0-win32-superpack-python2.6.exe>`_. Gnuplot-py 1.8 needs NumPy.
 * `Gnuplot-py <http://gnuplot-py.sourceforge.net/>`_: `gnuplot-py-1.8.zip <http://downloads.sourceforge.net/project/gnuplot-py/Gnuplot-py/1.8/gnuplot-py-1.8.zip>`_. Extract to temp dir, open command prompt, change to tempdir and type ``python setup.py install``.

2D Graphics (``psdump``, ``pdfdump``)

 * `PyX <http://pyx.sourceforge.net/>`_: `PyX-0.10.tar.gz <http://mesh.dl.sourceforge.net/sourceforge/pyx/PyX-0.10.tar.gz>`_. Extract to temp dir, open command prompt, change to tempdir and type ``python setup.py install``
 * `MikTeX <http://miktex.org/>`_: `Basic MiKTeX 2.8 Installer <http://miktex.org/2.8/setup>`_. PyX needs a LaTeX installation. Choose an installation directory WITHOUT spaces (e.g. ``C:\MikTex2.8`` and add the ``(INSTALLDIR)\miktex\bin`` subdirectory to your PATH.

Graphs (conversations)

 * `Graphviz <http://www.graphviz.org/>`_: `graphviz-2.24.exe <http://www.graphviz.org/pub/graphviz/stable/windows/graphviz-2.24.msi>`_. Add ``(INSTALLDIR)\ATT\Graphviz\bin`` to your PATH.

3D Graphics (trace3d)

 * `VPython <http://www.vpython.org/>`_: `VPython-Win-Py2.5-3.2.11.exe <http://www.vpython.org/download/VPython-Win-Py2.5-3.2.11.exe>`_. No binary installer for Python 2.6 seems to be available yet.

WEP decryption

 * `PyCrypto <http://www.dlitz.net/software/pycrypto/>`_: `pycrypto-2.1.0.win32-py2.5.zip <http://www.voidspace.org.uk/downloads/pycrypto-2.1.0.win32-py2.5.zip>`_ `pycrypto-2.1.0.win32-py2.6.zip <http://www.voidspace.org.uk/downloads/pycrypto-2.1.0.win32-py2.6.zip>`_

Fingerprinting

  * `Nmap <http://nmap.org>`_. `nmap-4.20-setup.exe <http://download.insecure.org/nmap/dist-old/nmap-4.20-setup.exe>`_. If you use the default installation directory, Scapy should automatically find the fingerprints file.
  * Queso: `queso-980922.tar.gz <http://www.packetstormsecurity.org/UNIX/scanners/queso-980922.tar.gz>`_. Extract the tar.gz file (e.g. using `7-Zip <http://www.7-zip.org/>`_) and put ``queso.conf`` into your Scapy directory


Screenshot
^^^^^^^^^^

.. image:: graphics/scapy-win-screenshot2.png
   :scale: 80
   :align: center

Known bugs
^^^^^^^^^^

 * You may not be able to capture WLAN traffic on Windows. Reasons are explained on the Wireshark wiki and in the WinPcap FAQ. Try switching off promiscuous mode with ``conf.sniff_promisc=False``.
 * Packets cannot be sent to localhost (or local IP addresses on your own host).
 * The ``voip_play()`` functions do not work because they output the sound via ``/dev/dsp`` which is not available on Windows. 
 
 


