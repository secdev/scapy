## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

"""
All layers. Configurable with conf.load_layers.
"""

import __builtin__
from scapy.config import conf
from scapy.error import log_loading
import logging, importlib
ignored = list(__builtin__.__dict__.keys()) + ["sys"]
log = logging.getLogger("scapy.loading")

__all__ = []


def _validate_local(x):
    """Returns whether or not a variable should be imported.
    Will return False for any default modules (sys), or if
    they are detected as private vars (starting with a _)"""
    global ignored
    return x[0] != "_" and not x in ignored

def _import_star(m):
    mod = importlib.import_module("." + m, "scapy.layers")
    if '__all__' in mod.__dict__:
        # only import the exported symbols in __all__
        for name in mod.__dict__['__all__']:
            __all__.append(name)
            globals()[name] = mod.__dict__[name]
    else:
        # import all the non-private symbols
        for name, sym in mod.__dict__.iteritems():
            if _validate_local(name):
                __all__.append(name)
                globals()[name] = sym

for _l in conf.load_layers:
    log_loading.debug("Loading layer %s" % _l)
    try:
        if _l != "tls":
            _import_star(_l)
    except Exception as e:
        log.warning("can't import layer %s: %s" % (_l,e))

