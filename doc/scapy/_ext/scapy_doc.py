# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Gabriel Potter <gabriel@potter.fr>
# This program is published under a GPLv2 license

"""
A Sphinx Extension for Scapy's doc preprocessing
"""

import subprocess
import os
from scapy.packet import Packet, _pkt_ls, rfc

from sphinx.ext.autodoc import AttributeDocumenter

# Utils

def generate_rest_table(items):
    """
    Generates a ReST table from a list of tuples
    """
    lengths = [max(len(y) for y in x) for x in zip(*items)]
    sep = "+%s+" % "+".join("-" * x for x in lengths)
    sized = "|%s|" % "|".join("{:%ss}" % x for x in lengths)
    output = []
    for i in items:
        output.append(sep)
        output.append(sized.format(*i))
    output.append(sep)
    return output


def tab(items):
    """
    Tabulize a generator.
    """
    for i in items:
        # Tabs are 3-wide in autodoc
        yield "   " + i


def class_ref(cls):
    """
    Get Sphinx reference to a class
    """
    return ":class:`~%s`" % (
        cls.__module__ + '.' + cls.__name__
    )


def get_fields_desc(obj):
    """
    Create a readable documentation for fields_desc
    """
    output = []
    for value in _pkt_ls(obj):
        fname, cls, clsne, dflt, long_attrs = value
        output.append(
            (
                "**%s**" % fname,
                class_ref(cls) + ((" " + clsne) if clsne else ""),
                "``%s``" % dflt
            )
        )
    if output:
        output = list(
            tab(
                generate_rest_table(output)
            )
        )
        # Add header
        output.insert(0, ".. table:: %s fields" % obj.__name__)
        output.insert(1, "   :widths: grid")
        output.insert(2, "   ")
        # Add RFC-like graph
        try:
            graph = list(tab(rfc(obj, ret=True).split("\n")))
        except AttributeError:
            return output
        s = "Display RFC-like schema"
        graph.insert(0, ".. raw:: html")
        graph.insert(1, "")
        graph.insert(2, "   <details><summary>%s</summary><code><pre>" % s)
        graph.append("   </pre></code></details>")
        graph.append("")
        return graph + output
    return output

# Documenter

class AttrsDocumenter(AttributeDocumenter):
    """
    Mock of AttributeDocumenter to handle Scapy settings
    """

    def add_directive_header(self, *args, **kwargs):
        def call_parent():
            """Calls the super.super.add_directive_header"""
            super(AttributeDocumenter, self).add_directive_header(
                *args, **kwargs
            )
        sourcename = self.get_sourcename()
        # Custom additions
        if issubclass(self.parent, Packet):
            # Packet
            if self.object_name == "fields_desc":
                # Display custom field table
                call_parent()
                table = list(tab(get_fields_desc(self.parent)))
                if table:
                    self.add_line("   ", sourcename)
                    for line in table:
                        self.add_line(line, sourcename)
                    self.add_line("   ", sourcename)
                return
            elif self.object_name == "payload_guess":
                # Display list of possible children
                call_parent()
                children = sorted(set(class_ref(x[1]) for x in self.object))
                if children:
                    lines = [
                        "",
                        "Possible sublayers:",
                        ", ".join(children),
                        ""
                    ]
                    for line in tab(lines):
                        self.add_line(line, sourcename)
                return
            elif (self.object_name in ["aliastypes"] or
                  self.object_name.startswith("class_")):
                # Ignore
                call_parent()
                return
        # The field is unknown: continue normally
        super(AttrsDocumenter, self).add_directive_header(*args, **kwargs)

# Setup

def builder_inited_handler(app): 
    """Generate API tree"""
    if int(os.environ.get("SCAPY_APITREE", True)):
        subprocess.call(['tox', '-e', 'apitree'])


def setup(app):
    """
    Entry point of the scapy_doc extension.

    Called by sphinx while booting up.
    """
    app.add_autodocumenter(AttrsDocumenter, override=True)
    app.connect('builder-inited', builder_inited_handler)

    # Dummy. We won't publish this
    return {
        'version': '1.0',
        'parallel_read_safe': True,
        'parallel_write_safe': True,
    }
