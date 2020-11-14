.. Scapy documentation master file, created by sphinx-quickstart on Mon Sep  8 19:37:39 2008.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to Scapy's documentation!
=================================

.. image:: graphics/scapy_logo.png
   :scale: 20
   :align: center

:Version: |version|
:Release: |release|
:Date: |today|

This document is under a `Creative Commons Attribution - Non-Commercial 
- Share Alike 2.5 <http://creativecommons.org/licenses/by-nc-sa/2.5/>`_ license.

.. toctree::
   :maxdepth: 2
   :caption: General documentation
   
   introduction
   installation
   
   usage
   advanced_usage
   routing

.. toctree::
   :maxdepth: 2
   :caption: Extend scapy

   extending
   build_dissect
   functions

.. toctree::
   :maxdepth: 2
   :caption: Layer-specific documentation
   :glob:

   layers/index.rst

.. toctree::
   :maxdepth: 2
   :caption: About

   troubleshooting
   development
   backmatter

.. only:: html

    .. toctree::
       :maxdepth: 1
       :titlesonly:
       :caption: API Reference

       api/scapy.rst
 
