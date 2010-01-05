## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

from scapy.config import conf
from scapy.error import log_loading

def _import_star(m):
    mod = __import__(m, globals(), locals())
    for k,v in mod.__dict__.iteritems():
        globals()[k] = v

for _l in conf.load_layers:
    log_loading.debug("Loading layer %s" % _l)
    _import_star(_l)




