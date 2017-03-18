## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

"""
All layers. Configurable with conf.load_layers.
"""

from __future__ import absolute_import
from scapy.config import conf
from scapy.error import log_loading
import logging
import six
import six.moves.builtins
import importlib
log = logging.getLogger("scapy.loading")

__all__ = []

def _import_star(m):
    mod = importlib.import_module("." + m, "scapy.layers")
    if '__all__' in mod.__dict__:
        # only import the exported symbols in __all__
        for name in mod.__dict__['__all__']:
            __all__.append(name)
            globals()[name] = mod.__dict__[name]
    else:
        # import all the non-private symbols
        for name, sym in six.iteritems(mod.__dict__):
            if name[0] != '_':
                __all__.append(name)
                globals()[name] = sym

for _l in conf.load_layers:
    log_loading.debug("Loading layer %s" % _l)
    try:
        if _l != "tls":
            _import_star(_l)
    except Exception as e:
        raise
        log.warning("can't import layer %s: %s" % (_l,e))

