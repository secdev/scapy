.. highlight:: sh

*************************
Download and Installation
*************************

Overview
========

 0. Install `Python 2.7.X or 3.4+ <https://www.python.org/downloads/>`_.
 1. `Download and install Scapy. <#installing-scapy-v2-x>`_
 2. `Follow the platform-specific instructions (dependencies) <#platform-specific-instructions>`_.
 3. (Optional): `Install additional software for special features <#optional-software-for-special-features>`_.
 4. Run Scapy with root privileges.
 
Each of these steps can be done in a different way depending on your platform and on the version of Scapy you want to use.  Follow the platform-specific instructions for more detail.

Scapy versions
==============

.. raw:: html

   <div id="table_div" style="text-align:center;"></div>
   <script type="text/javascript" src="https://www.gstatic.com/charts/loader.js"></script>
   <script type="text/javascript" src="https://scapy.net/assets/js/scapy_versions.js"></script>
   <br />

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
   To get the latest versions, with bugfixes and new features, but maybe not as stable, see the `development version <#current-development-version>`_.

Use pip::

$ pip install --pre scapy[basic]

In fact, since 2.4.3, Scapy comes in 3 bundles:

+----------+------------------------------------------+---------------------------------------+
| Bundle   | Contains                                 | Pip command                           |
+==========+==========================================+=======================================+
| Default  | Only Scapy                               | ``pip install scapy``                 |
+----------+------------------------------------------+---------------------------------------+
| Basic    | Scapy & IPython. **Highly recommended**  | ``pip install --pre scapy[basic]``    |
+----------+------------------------------------------+---------------------------------------+
| Complete | Scapy & all its main dependencies        | ``pip install --pre scapy[complete]`` |
+----------+------------------------------------------+---------------------------------------+

 
Current development version
----------------------------

.. index::
   single: Git, repository

If you always want the latest version with all new features and bugfixes, use Scapy's Git repository:

1. `Install the Git version control system <https://git-scm.com/book/en/v2/Getting-Started-Installing-Git>`_.

2. Check out a clone of Scapy's repository::

   $ git clone https://github.com/secdev/scapy.git

.. note::
	You can also download Scapy's `latest version <https://github.com/secdev/scapy/archive/master.zip>`_ in a zip file::

	$ wget --trust-server-names https://github.com/secdev/scapy/archive/master.zip   # or wget -O master.zip https://github.com/secdev/scapy/archive/master.zip
	$ unzip master.zip
	$ cd master

3. Install Scapy in the standard `distutils <https://docs.python.org/3/distutils/setupscript.html>`_ way:: 

   $ cd scapy
   $ sudo python setup.py install

If you used Git, you can always update to the latest version afterwards::

   $ git pull
   $ sudo python setup.py install

.. note::

   You can run scapy without installing it using the ``run_scapy`` (unix) or ``run_scapy.bat`` (Windows) script or running it directly from the executable zip file (see the previous section).

Optional Dependencies
=====================

For some special features, Scapy will need some dependencies to be installed.
Most of those software are installable via ``pip``.
Here are the topics involved and some examples that you can use to try if your installation was successful.

.. index::
   single: plot()

* Plotting. ``plot()`` needs `Matplotlib <https://matplotlib.org/>`_.

  Matplotlib is installable via ``pip install matplotlib``
 
  .. code-block:: python
   
    >>> p=sniff(count=50)
    >>> p.plot(lambda x:len(x))
 
* 2D graphics. ``psdump()`` and ``pdfdump()`` need `PyX <http://pyx.sourceforge.net/>`_ which in turn needs a LaTeX distribution: `texlive (Unix) <http://www.tug.org/texlive/>`_ or `MikTex (Windows) <https://miktex.org/>`_.
  
  Note: PyX requires version <=0.12.1 on Python 2.7. This means that on Python 2.7, it needs to be installed via ``pip install pyx==0.12.1``. Otherwise ``pip install pyx``
  
  .. code-block:: python
   
    >>> p=IP()/ICMP()
    >>> p.pdfdump("test.pdf") 
 
* Graphs. ``conversations()`` needs `Graphviz <http://www.graphviz.org/>`_ and `ImageMagick <http://www.imagemagick.org/>`_.
 
  .. code-block:: python

    >>> p=rdpcap("myfile.pcap")
    >>> p.conversations(type="jpg", target="> test.jpg")

  .. note::
    ``Graphviz`` and ``ImageMagick`` need to be installed separately, using your platform-specific package manager.

* 3D graphics. ``trace3D()`` needs `VPython-Jupyter <https://github.com/BruceSherwood/vpython-jupyter/>`_.

  VPython-Jupyter is installable via ``pip install vpython``

  .. code-block:: python

    >>> a,u=traceroute(["www.python.org", "google.com","slashdot.org"])
    >>> a.trace3D()

.. index::
   single: WEP, unwep()

* WEP decryption. ``unwep()`` needs `cryptography <https://cryptography.io>`_. Example using a `Weplap test file <http://weplab.sourceforge.net/caps/weplab-64bit-AA-managed.pcap>`_:

  Cryptography is installable via ``pip install cryptography``

  .. code-block:: python

    >>> enc=rdpcap("weplab-64bit-AA-managed.pcap")
    >>> enc.show()
    >>> enc[0]
    >>> conf.wepkey="AA\x00\x00\x00"
    >>> dec=Dot11PacketList(enc).toEthernet()
    >>> dec.show()
    >>> dec[0]
 
* PKI operations and TLS decryption. `cryptography <https://cryptography.io>`_ is also needed.

* Fingerprinting. ``nmap_fp()`` needs `Nmap <http://nmap.org>`_. You need an `old version <http://nmap.org/dist-old/>`_ (before v4.23) that still supports first generation fingerprinting.

  .. code-block:: python 
  
    >>> load_module("nmap")
    >>> nmap_fp("192.168.0.1")
    Begin emission:
    Finished to send 8 packets.
    Received 19 packets, got 4 answers, remaining 4 packets
    (0.88749999999999996, ['Draytek Vigor 2000 ISDN router'])
 
* VOIP. ``voip_play()`` needs `SoX <http://sox.sourceforge.net/>`_.

Platform-specific instructions
==============================

As a general rule, you can toggle the **libpcap** integration `on` or `off` at any time, using::

    from scapy.config import conf
    conf.use_pcap = True

Linux native
------------

Scapy can run natively on Linux, without libpcap.

* Install `Python 2.7 or 3.4+ <http://www.python.org>`_.
* Install `tcpdump <http://www.tcpdump.org>`_ and make sure it is in the $PATH. (It's only used to compile BPF filters (``-ddd option``))
* Make sure your kernel has Packet sockets selected (``CONFIG_PACKET``)
* If your kernel is < 2.6, make sure that Socket filtering is selected ``CONFIG_FILTER``) 

Debian/Ubuntu/Fedora
--------------------

Make sure tcpdump is installed:

- Debian/Ubuntu:

.. code-block:: text

    $ sudo apt-get install tcpdump

- Fedora:

.. code-block:: text

	$ yum install tcpdump

Then install Scapy via ``pip`` or ``apt`` (bundled under ``python-scapy``)
All dependencies may be installed either via the platform-specific installer, or via PyPI. See `Optional Dependencies <#optional-dependencies>`_ for more information.


Mac OS X
--------

On Mac OS X, Scapy **DOES work natively** since the recent versions.
However, you may want to make Scapy use libpcap.
You can choose to install it using either Homebrew or MacPorts. They both
work fine, yet Homebrew is used to run unit tests with
`Travis CI <https://travis-ci.org>`_. 

.. note:: 
    Libpcap might already be installed on your platform (for instance, if you have tcpdump). This is the case of `OSX <https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/pcap.3.html>`_

Install using Homebrew
^^^^^^^^^^^^^^^^^^^^^^

1. Update Homebrew::

   $ brew update

2. Install libpcap::

   $ brew install libpcap

Enable it In Scapy::

    conf.use_pcap = True

Install using MacPorts
^^^^^^^^^^^^^^^^^^^^^^

1. Update MacPorts::

   $ sudo port -d selfupdate

2. Install libpcap::

   $ sudo port install libpcap

Enable it In Scapy::

    conf.use_pcap = True

OpenBSD
-------

In a similar manner, to install Scapy on OpenBSD 5.9+, you **may** want to install libpcap, if you do not want to use the native extension:

.. code-block:: text

	$ doas pkg_add libpcap tcpdump

Then install Scapy via ``pip`` or ``pkg_add`` (bundled under ``python-scapy``)
All dependencies may be installed either via the platform-specific installer, or via PyPI. See `Optional Dependencies <#optional-dependencies>`_ for more information.

SunOS / Solaris
---------------

Solaris / SunOS requires ``libpcap`` (installed by default) to work.

.. note::
    In fact, Solaris doesn't support `AF_PACKET`, which Scapy uses on Linux, but rather uses its own system `DLPI`. See `this page <https://www.oracle.com/technetwork/server-storage/solaris/solaris-linux-app-139382.html>`_.
    We prefer using the very universal `libpcap` that spending time implementing support for `DLPI`.

.. _windows_installation:

Windows
-------

.. sectionauthor:: Dirk Loss <mail at dirk-loss.de>

Scapy is primarily being developed for Unix-like systems and works best on those platforms. But the latest version of Scapy supports Windows out-of-the-box. So you can use nearly all of Scapy's features on your Windows machine as well.

.. image:: graphics/scapy-win-screenshot1.png
   :scale: 80
   :align: center

You need the following software in order to install Scapy on Windows:

  * `Python <http://www.python.org>`_: `Python 2.7.X or 3.4+ <https://www.python.org/downloads/>`_. After installation, add the Python installation directory and its \Scripts subdirectory to your PATH. Depending on your Python version, the defaults would be ``C:\Python27`` and ``C:\Python27\Scripts`` respectively.
  * `Npcap <https://nmap.org/npcap/>`_: `the latest version <https://nmap.org/npcap/#download>`_. Default values are recommended. Scapy will also work with Winpcap.
  * `Scapy <http://www.secdev.org/projects/scapy/>`_: `latest development version <https://github.com/secdev/scapy/archive/master.zip>`_ from the `Git repository <https://github.com/secdev/scapy>`_. Unzip the archive, open a command prompt in that directory and run ``python setup.py install``. 

Just download the files and run the setup program. Choosing the default installation options should be safe. (In the case of ``Npcap``, Scapy **will work** with ``802.11`` option enabled. You might want to make sure that this is ticked when installing).

After all packages are installed, open a command prompt (cmd.exe) and run Scapy by typing ``scapy``. If you have set the PATH correctly, this will find a little batch file in your ``C:\Python27\Scripts`` directory and instruct the Python interpreter to load Scapy.

If really nothing seems to work, consider skipping the Windows version and using Scapy from a Linux Live CD -- either in a virtual machine on your Windows host or by booting from CDROM: An older version of Scapy is already included in grml and BackTrack for example. While using the Live CD you can easily upgrade to the latest Scapy version by using the `above installation methods <#installing-scapy-v2-x>`_.

Screenshot
^^^^^^^^^^

.. image:: graphics/scapy-win-screenshot2.png
   :scale: 80
   :align: center

Known bugs
^^^^^^^^^^

You may bump into the following bugs, which are platform-specific, if Scapy didn't manage work around them automatically:

 * You may not be able to capture WLAN traffic on Windows. Reasons are explained on the `Wireshark wiki <https://wiki.wireshark.org/CaptureSetup/WLAN>`_ and in the `WinPcap FAQ <https://www.winpcap.org/misc/faq.htm>`_. Try switching off promiscuous mode with ``conf.sniff_promisc=False``.
 * Packets sometimes cannot be sent to localhost (or local IP addresses on your own host).
 
Winpcap/Npcap conflicts
^^^^^^^^^^^^^^^^^^^^^^^

As ``Winpcap`` is becoming old, it's recommended to use ``Npcap`` instead. ``Npcap`` is part of the ``Nmap`` project.

.. note::
    This does NOT apply for Windows XP, which isn't supported by ``Npcap``.

1. If you get the message ``'Winpcap is installed over Npcap.'`` it means that you have installed both Winpcap and Npcap versions, which isn't recommended.

You may first **uninstall winpcap from your Program Files**, then you will need to remove::

    C:/Windows/System32/wpcap.dll
    C:/Windows/System32/Packet.dll

And if you are on an x64 machine::

   C:/Windows/SysWOW64/wpcap.dll
   C:/Windows/SysWOW64/Packet.dll

To use ``Npcap`` instead, as those files are not removed by the ``Winpcap`` un-installer.

2. If you get the message ``'The installed Windump version does not work with Npcap'`` it surely means that you have installed an old version of ``Windump``, made for ``Winpcap``.
Download the correct one on https://github.com/hsluoyz/WinDump/releases

In some cases, it could also mean that you had installed ``Npcap`` and ``Winpcap``, and that ``Windump`` is using ``Winpcap``. Fully delete ``Winpcap`` using the above method to solve the problem.

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

You can now open the resulting HTML file ``_build/html/index.html`` in your favorite web browser.

To use the ReadTheDocs' template, you will have to install the corresponding theme with: ::

   pip install sphinx_rtd_theme

UML diagram
-----------
Using ``pyreverse`` you can build a UML representation of the Scapy source code's object hierarchy. Here is an
example of how to build the inheritance graph for the Fields objects : ::

   (activate a virtualenv)
   pip install pylint
   cd scapy/
   pyreverse -o png -p fields scapy/fields.py

This will generate a ``classes_fields.png`` picture containing the inheritance hierarchy. Note that you can provide as many
modules or packages as you want, but the result will quickly get unreadable.

To see the dependencies between the DHCP layer and the ansmachine module, you can run: ::

   pyreverse -o png -p dhcp_ans scapy/ansmachine.py scapy/layers/dhcp.py scapy/packet.py

In this case, Pyreverse will also generate a ``packages_dhcp_ans.png`` showing the link between the different python modules provided.
