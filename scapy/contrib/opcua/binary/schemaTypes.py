# coding=utf-8
"""
This module generates all OPC UA types that are defined in the Opc.Ua.Types.bsd file using the schemaParser module.
It adds all generated classes to its own global namespace so it can be used like the other types modules.

If all OPC UA basic data types are needed load the uaTypes module
"""
from enum import Enum

from scapy.contrib.opcua.binary.schema.schemaParser import SchemaParser
import sys
import logging
_logger = logging.getLogger(__name__)

nodeIdMappings = {}
statusCodes = {}


class UaStatusCodes(Enum):
    pass


def _populate_module(model):
    _logger.debug("Populating module...")
    thismodule = sys.modules[__name__]
    for name, cls in model.classes.items():
        setattr(thismodule, "Ua" + name, cls)
    for name, cls in model.enums.items():
        setattr(thismodule, "Ua" + name, cls)
    thismodule.nodeIdMappings = model.nodeIdMappings
    
    for id, (name, _) in model.statusCodes.items():
        setattr(UaStatusCodes, name, id)
    
    thismodule.statusCodes = model.statusCodes
    _logger.debug("Done!")


_parser = SchemaParser()
_parser.parse()
_populate_module(_parser.model)
