.. highlight:: sh

*************************
Download and Installation
*************************

Overview
========

 0. Install `Python 2.7.X <https://www.python.org/downloads/>`_.
 1. `Download and install Scapy. <#installing-scapy-v2-x>`_
 2. `Follow the platform specific instructions (depedencies) <#platform-specific-instructions>`_.
 3. (Optional): `Install additional software <#optional-packages>`_ for `special features <#optional-software-for-special-features>`_.
 4. Run Scapy with root privileges.
 
Each of these steps can be done in a different way dependent on your platform and on the version of Scapy you want to use. 

At the moment, there are two different versions of Scapy:

* **Scapy v1.x**. It consists of only one file and works on Python 2.4, so it might be easier to install.
  Moreover, your OS may already have a specially prepared packages or ports for it. Last version is v1.2.2.
* **Scapy v2.x**. The current development version adds several features (e.g. IPv6). It consists of several
  files  packaged in the standard distutils way. Scapy v2 <= 2.3.3 needs Python 2.5, Scapy v2 > 2.3.3 needs
  Python 2.7.

.. note::

   In Scapy v2 use ``from scapy.all import *`` instead of ``from scapy import *``.


Installing Scapy v2.x
=====================

The following steps describe how to install (or update) Scapy itself.
Dependent on your platform, some additional libraries might have to be installed to make it actually work. 
So please also have a look at the platform specific chapters on how to install those requirements.

.. note::

   The following steps apply to Unix-like operating systems (Linux, BSD, Mac OS X). 
   For Windows, see the  `special chapter <#windows>`_ below.

Make sure you have Python installed before you go on.

Latest release
--------------

.. note::
   To get the latest versions, with bugsfixes and new features, but maybe not as stable, see the `development version <#current-development-version>`_.

Use pip::

$ pip install scapy


You can also download the `latest version <http://scapy.net>`_ to a temporary directory and install it in the standard `distutils <http://docs.python.org/inst/inst.html>`_ way::

$ cd /tmp
$ wget --trust-server-names scapy.net   # or wget -O scapy.zip scapy.net
$ unzip scapy-x.x.x.zip
$ cd scapy
$ sudo python setup.py install
 
Alternatively, you can execute the zip file::

$ chmod +x scapy-x.x.x.zip
$ sudo ./scapy-x.x.x.zip

or::

$ sudo sh scapy-x.x.x.zip

or::

$ mv scapy-x.x.x.zip /usr/local/bin/scapy
$ sudo scapy

or::

$ chmod +x scapy-x.x.x.zip
$ ./scapy-x.x.x.zip

or download and run in one command::
  
$ sh <(curl -sL scapy.net)

.. note::

   To make a zip executable, some bytes have been added before the zip header.
   Most zip programs handle this, but not all. If your zip program complains
   about the zip file to be corrupted, either change it, or download a 
   non-executable zip at https://github.com/secdev/scapy/archive/master.zip

 
Current development version
----------------------------

.. index::
   single: Git, repository

If you always want the latest version with all new features and bugfixes, use Scapy's Git repository:

1. Install the Git version control system. For example, on Debian/Ubuntu use::

      $ sudo apt-get install git

   or on OpenBSD:: 
    
      $ doas pkg_add git

2. Check out a clone of Scapy's repository::
    
   $ git clone https://github.com/secdev/scapy
    
3. Install Scapy in the standard distutils way:: 
    
   $ cd scapy
   $ sudo python setup.py install
    
Then you can always update to the latest version::

   $ git pull
   $ sudo python setup.py install

.. note::

   You can run scapy without installing it using the ``run_scapy`` (unix) or ``run_scapy.bat`` (Windows) script or running it directly from the executable zip file (see previous section).

Installing Scapy v1.2 (Deprecated)
==================================

As Scapy v1 consists only of one single Python file, installation is easy:
Just download the last version and run it with your Python interpreter::

 $ wget https://raw.githubusercontent.com/secdev/scapy/v1.2.0.2/scapy.py
 $ sudo python scapy.py

Optional software for special features
======================================

For some special features you have to install more software. 
Platform-specific instructions on how to install those packages can be found in the next chapter.
Here are the topics involved and some examples that you can use to try if your installation was successful.

.. index::
   single: plot()

* Plotting. ``plot()`` needs `Gnuplot-py <http://gnuplot-py.sourceforge.net/>`_ which needs `GnuPlot <http://www.gnuplot.info/>`_ and `NumPy <http://numpy.scipy.org/>`__.
 
  .. code-block:: python
   
     >>> p=sniff(count=50)
     >>> p.plot(lambda x:len(x))
 
* 2D graphics. ``psdump()`` and ``pdfdump()`` need `PyX <http://pyx.sourceforge.net/>`_ which in turn needs a `LaTeX distribution <http://www.tug.org/texlive/>`_. For viewing the PDF and PS files interactively, you also need `Adobe Reader <http://www.adobe.com/products/reader/>`_ (``acroread``) and `gv <http://wwwthep.physik.uni-mainz.de/~plass/gv/>`_ (``gv``). 
  
  .. code-block:: python
   
     >>> p=IP()/ICMP()
     >>> p.pdfdump("test.pdf") 
 
* Graphs. ``conversations()`` needs `Graphviz <http://www.graphviz.org/>`_ and `ImageMagick <http://www.imagemagick.org/>`_.
 
  .. code-block:: python

     >>> p=readpcap("myfile.pcap")
     >>> p.conversations(type="jpg", target="> test.jpg")
 
* 3D graphics. ``trace3D()`` needs `VPython <http://www.vpython.org/>`_.
 
  .. code-block:: python

     >>> a,u=traceroute(["www.python.org", "google.com","slashdot.org"])
     >>> a.trace3D()

.. index::
   single: WEP, unwep()

* WEP decryption. ``unwep()`` needs `cryptography <https://cryptography.io>`_. Example using a `Weplap test file <http://weplab.sourceforge.net/caps/weplab-64bit-AA-managed.pcap>`_:

  .. code-block:: python

     >>> enc=rdpcap("weplab-64bit-AA-managed.pcap")
     >>> enc.show()
     >>> enc[0]
     >>> conf.wepkey="AA\x00\x00\x00"
     >>> dec=Dot11PacketList(enc).toEthernet()
     >>> dec.show()
     >>> dec[0]
 
* PKI operations and TLS decryption. `cryptography <https://cryptography.io>` is also needed.

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

* Install `Python 2.7 <http://www.python.org>`_.
* Install `tcpdump <http://www.tcpdump.org>`_ and make sure it is in the $PATH. (It's only used to compile BPF filters (``-ddd option``))
* Make sure your kernel has Packet sockets selected (``CONFIG_PACKET``)
* If your kernel is < 2.6, make sure that Socket filtering is selected ``CONFIG_FILTER``) 

Debian/Ubuntu
-------------

Just use the standard packages::

$ sudo apt-get install tcpdump graphviz imagemagick python-gnuplot python-cryptography python-pyx

Scapy optionally uses python-cryptography v1.7 or later. It has not been packaged for ``apt`` in less recent OS versions (e.g. Debian Jessie). If you need the cryptography-related methods, you may install the library with:

.. code-block:: text

    # pip install cryptography

Fedora
------

Here's how to install Scapy on Fedora 9:

.. code-block:: text

    # yum install git python-devel
    # cd /tmp
    # git clone https://github.com/secdev/scapy
    # cd scapy
    # python setup.py install
    
Some optional packages:

.. code-block:: text

    # yum install graphviz python-cryptography sox PyX gnuplot numpy
    # cd /tmp
    # wget http://heanet.dl.sourceforge.net/sourceforge/gnuplot-py/gnuplot-py-1.8.tar.gz
    # tar xvfz gnuplot-py-1.8.tar.gz
    # cd gnuplot-py-1.8
    # python setup.py install


Mac OS X
--------

On Mac OS X, Scapy does not work natively. You need to install Python bindings
to use libdnet and libpcap. You can choose to install using either Homebrew or
MacPorts. They both work fine, yet Homebrew is used to run unit tests with
`Travis CI <https://travis-ci.org>`_. 


Install using Homebrew
^^^^^^^^^^^^^^^^^^^^^^

1. Update Homebrew::

   $ brew update

2. Install Python bindings::


   $ brew install --with-python libdnet
   $ brew install https://raw.githubusercontent.com/secdev/scapy/master/.travis/pylibpcap.rb
   $ sudo brew install --with-python libdnet
   $ sudo brew install https://raw.githubusercontent.com/secdev/scapy/master/.travis/pylibpcap.rb


Install using MacPorts
^^^^^^^^^^^^^^^^^^^^^^

1. Update MacPorts::

   $ sudo port -d selfupdate

2. Install Python bindings::

   $ sudo port install py-libdnet py-pylibpcap


OpenBSD
-------

Here's how to install Scapy on OpenBSD 5.9+

.. code-block:: text

 $ doas pkg_add py-libpcap py-libdnet git
 $ cd /tmp
 $ git clone http://github.com/secdev/scapy
 $ cd scapy
 $ doas python2.7 setup.py install


Optional packages (OpenBSD only)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

py-cryptography

.. code-block:: text

 # pkg_add py-cryptography

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

 # wget http://git.netfilter.org/ebtables/plain/ethertypes -O /etc/ethertypes

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

  * `Python <http://www.python.org>`_: `python-2.7.13.amd64.msi <https://www.python.org/ftp/python/2.7.13/python-2.7.13.amd64.msi>`_ (64bits) or `python-2.7.13.msi <https://www.python.org/ftp/python/2.7.13/python-2.7.13.msi>`_ (32bits). After installation, add the Python installation directory and its \Scripts subdirectory to your PATH. Depending on your Python version, the defaults would be ``C:\Python27`` and ``C:\Python27\Scripts`` respectively.
  * `Npcap <https://nmap.org/npcap/>`_: `the latest version <https://nmap.org/npcap/#download>`_. Default values are recommanded. Scapy will also work with Winpcap.
  * `Scapy <http://www.secdev.org/projects/scapy/>`_: `latest development version <https://github.com/secdev/scapy/archive/master.zip>`_ from the `Git repository <https://github.com/secdev/scapy>`_. Unzip the archive, open a command prompt in that directory and run "python setup.py install". 

Just download the files and run the setup program. Choosing the default installation options should be safe.

For your convenience direct links are given to the version that is supported (Python 2.7). If these links do not work or if you are using a different Python version (which will surely not work), just visit the homepage of the respective package and look for a Windows binary. As a last resort, search the web for the filename.

After all packages are installed, open a command prompt (cmd.exe) and run Scapy by typing ``scapy``. If you have set the PATH correctly, this will find a little batch file in your ``C:\Python27\Scripts`` directory and instruct the Python interpreter to load Scapy.

If really nothing seems to work, consider skipping the Windows version and using Scapy from a Linux Live CD -- either in a virtual machine on your Windows host or by booting from CDROM: An older version of Scapy is already included in grml and BackTrack for example. While using the Live CD you can easily upgrade to the latest Scapy version by typing ``cd /tmp && wget scapy.net``.

Optional packages
^^^^^^^^^^^^^^^^^

.. note::
   If you are using OpenBSD, follow `this <#optional-packages-openbsd-only>`__ instead

1. (Recommanded) Auto install: Using pip
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

 Plotting (``plot``): 

  * GnuPlot and Gnuplot-py need a manual install.
  * Install Numpy:
  
    .. code-block:: text

        # pip install numpy 
 
 2D Graphics (``psdump``, ``pdfdump``):
 
  * MikTeX need a manual install.
  * Install pyx:
 
    .. code-block:: text

        # pip install pyx
        
 Graphs (conversations):
 
  * Install graphviz:

    .. code-block:: text
     
        # pip install graphviz
        
 3D Graphics (trace3d):
 
  * Install VPython:
  
    .. code-block:: text
     
        # pip install vpython
        
 WEP decryption:
 
  * Install cryptography:
    
    .. code-block:: text
     
        # pip install cryptography
       
 Fingerprinting:
 
 * Nmap and Queso need to be installed manualy.
 
2. (Advanced) Manual install
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

 Plotting (``plot``)

 * `GnuPlot <http://www.gnuplot.info/>`_: `gp504-win64-mingw.exe <https://sourceforge.net/projects/gnuplot/files/gnuplot/5.0.4/gp504-win64-mingw.exe/download>`_ (64bits) or `gp504-win32-mingw.exe <https://sourceforge.net/projects/gnuplot/files/gnuplot/5.0.4/gp504-win32-mingw.exe/download>`_ (32bits).
 * `NumPy <http://www.numpy.org/>`_: `numpy-1.11.2.zip <https://sourceforge.net/projects/numpy/files/NumPy/1.11.2/numpy-1.11.2.zip/download>`_. Extract to temp dir, open command prompt, change to tempdir and type ``python setup.py install``. Gnuplot-py 1.8 needs NumPy.
 * `Gnuplot-py <http://gnuplot-py.sourceforge.net/>`_: `gnuplot-py-1.8.zip <http://downloads.sourceforge.net/project/gnuplot-py/Gnuplot-py/1.8/gnuplot-py-1.8.zip>`_. As numpy, use a tempdir.

 2D Graphics (``psdump``, ``pdfdump``)

 * `PyX <http://pyx.sourceforge.net/>`_: `PyX-0.14.1.tar.gz <https://pypi.python.org/packages/b4/a0/75d9d39bbd0bcd3aac7bf909b1c356188734a865552607a8c6bba3bf30bd/PyX-0.14.1.tar.gz>`_. Extract to temp dir, open command prompt, change to tempdir and type ``python setup.py install``
 * `MikTeX <http://miktex.org/>`_: `Basic MiKTeX 2.8 Installer <https://miktex.org/2.9/setup>`_. PyX needs a LaTeX installation. Choose an installation directory WITHOUT spaces (e.g. ``C:\MikTex2.8`` and check that the ``(INSTALLDIR)\miktex\bin`` subdirectory is added to your PATH.

 Graphs (conversations)

 * `Graphviz <http://www.graphviz.org/>`_: `graphviz-2.38.exe <http://www.graphviz.org/pub/graphviz/stable/windows/graphviz-2.38.msi>`_. Add ``(INSTALLDIR)\ATT\Graphviz\bin`` to your PATH.

 3D Graphics (trace3d)

 * `VPython <http://www.vpython.org/>`_: `VPython-Win-64-Py2.7-6.11.exe <http://sourceforge.net/projects/vpythonwx/files/6.11-release/VPython-Win-64-Py2.7-6.11.exe/download>`_ (64bits) or `VPython-Win-32-Py2.7-6.11.exe <http://sourceforge.net/projects/vpythonwx/files/6.11-release/VPython-Win-32-Py2.7-6.11.exe/download>`_ (32bits).

 WEP decryption

 * `cryptography <https://cryptography.io>`_: `HowTo <https://cryptography.io/en/latest/installation/#on-windows>`_

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
 * Packets sometimes cannot be sent to localhost (or local IP addresses on your own host).
 
Winpcap/Npcap conflicts
^^^^^^^^^^^^^^^^^^^^^^^

As Winpcap is becoming old, it's recommanded to use Npcap instead. Npcap is part of the Nmap project.

1. If you get the message 'Winpcap is installed over Npcap.' it means that you have installed both winpcap and npcap versions, which isn't recommanded.

You may uninstall winpcap from your Program Files, then you will need to remove:
 * C:/Windows/System32/wpcap.dll
 * C:/Windows/System32/Packet.dll

To use npcap instead.

2. If you get the message 'The installed Windump version does not work with Npcap' it means that you have installed an old version of Windump.
Download the correct one on https://github.com/hsluoyz/WinDump/releases

Build the documentation offline
===============================
The Scapy project's documentation is written using reStructuredText (files \*.rst) and can be built using
the `Sphinx <http://www.sphinx-doc.org/>`_ python library. The official online version is available
on `readthedocs <http://scapy.readthedocs.io/>`_.

HTML version
------------
The instructions to build the HTML version are: ::

   (activate a virtualenv)
   pip install sphinx
   cd doc/scapy
   make html

Or on windows, simply run ``BuildDoc.bat``

You can now open the resulting HTML file ``_build/html/index.html`` in your favorite web browser.

To use the ReadTheDocs' template, you will have to install the corresponding theme with: ::

   pip install sphinx_rtd_theme

If installed, it will be automatically used, but you may disable it by setting ``auto_rtd`` to ``False`` in ``doc/scapy/conf.py``

UML diagram
-----------
Using ``pyreverse`` you can build an UML representation of the Scapy source code's object hierarchy. Here is an
example on how to build the inheritence graph for the Fields objects : ::

   (activate a virtualenv)
   pip install pylint
   cd scapy/
   pyreverse -o png -p fields scapy/fields.py

This will generate a ``classes_fields.png`` picture containing the inheritance hierarchy. Note that you can provide as many
modules or packages as you want, but the result will quickly get unreadable.

To see the dependencies between the DHCP layer and the ansmachine module, you can run: ::

   pyreverse -o png -p dhcp_ans scapy/ansmachine.py scapy/layers/dhcp.py scapy/packet.py

In this case, Pyreverse will also generate a ``packages_dhcp_ans.png`` showing the link between the different python modules provided.
