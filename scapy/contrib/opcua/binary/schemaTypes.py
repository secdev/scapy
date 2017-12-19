# coding=utf-8

from scapy.contrib.opcua.binary.schema.schemaParser import SchemaParser
import sys

nodeIdMappings = {}


def _populate_module(model):
    print("Populating module...")
    thismodule = sys.modules[__name__]
    for name, cls in model.classes.items():
        setattr(thismodule, "Ua" + name, cls)
    thismodule.nodeIdMappings = model.nodeIdMappings
    print("Done!")


_parser = SchemaParser()
_parser.parse()
_populate_module(_parser.model)
