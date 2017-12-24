# coding=utf-8

import xml.etree.ElementTree as ElementTree
import sys
import re
import scapy.contrib.opcua.binary.builtinTypes
from scapy.contrib.opcua.helpers import UaTypePacket
from scapy.fields import PacketField, PacketListField, FieldListField
import logging
import csv
import os

class Field(object):

    def __init__(self):
        self.name = None
        self.fieldType = None
        self.lengthOf = None
        self.lengthFrom = None
        self.lengthInBytes = False

    def __str__(self):
        return "{{{}}}: {}".format(self.fieldType, self.name)


class Enum(object):
    def __init__(self):
        self.name = None
        self.lengthInBits = None
        self.values = []
        self.doc = ""

    def __str__(self):
        return "{{{}}}: {}".format(self.name, self.doc)


class EnumValue(object):
    def __init__(self):
        self.name = None
        self.value = None


class StructuredType(object):

    def __init__(self, name):
        self.name = name
        self.fields = []
        self.documentation = ""

    def __str__(self):
        return self.name


class Model(object):

    def __init__(self):
        self.builtins = {"PacketTypes": {}, "FieldTypes": {}}
        self.structuredTypes = []
        self.enumTypes = []
        self.classes = {}
        self.nodeIdMappings = {}
        self.enumFields = {}


class SchemaParser(object):
    class ParseError(Exception):
        pass

    def __init__(self, schemaPath=None, nodeIdsPath=None, builtins=None):
        """

        :param schemaPath: Path to the schema .bsd file
        :param builtins: A dict of builtins where the PacketTypes element is a dict of builtin Packet types and the
                         FieldTypes element a dict of builtin Field types. Each dict should contain a string identifier
                         and the associated class. If nothing is passed, the types are inferred from the
                         builtinTypes.py module.
        """

        if schemaPath is None:
            schemaPath = "Opc.Ua.Types.bsd"
            schemaPath = os.path.join(os.path.dirname(__file__), schemaPath)

        if nodeIdsPath is None:
            nodeIdsPath = "NodeIds.csv"
            nodeIdsPath = os.path.join(os.path.dirname(__file__), nodeIdsPath)

        self.logger = logging.getLogger(__name__)
        self.schemaPath = schemaPath
        self.nodeIdsPath = nodeIdsPath
        self.xmlSchema = None
        self.model = Model()
        self.reparse = []
        if builtins is None:
            self.model.builtins = {"PacketTypes": {}, "FieldTypes": {}}
            self._infer_builtins()
        else:
            self.model.builtins = builtins

    def _infer_builtins(self):
        types_dict = sys.modules["scapy.contrib.opcua.binary.builtinTypes"]

        for att in dir(types_dict):
            if att.startswith("Ua"):
                builtin = re.sub(r"^Ua|Field$", "", att)
                if builtin != '':
                    if att.endswith("Field"):
                        self.model.builtins["FieldTypes"][builtin] = getattr(types_dict, att)
                    else:
                        self.model.builtins["PacketTypes"][builtin] = getattr(types_dict, att)

        # Remove packet versions of builtins that have a field version
        for fieldType in self.model.builtins["FieldTypes"]:
            if fieldType in self.model.builtins["PacketTypes"]:
                self.model.builtins["PacketTypes"].pop(fieldType)
        self.logger.debug("Inferred {} builtin types".format(len(self.model.builtins["FieldTypes"]) +
                                                             len(self.model.builtins["PacketTypes"])))

    def _is_type_builtin(self, typeName):
        if typeName in self.model.builtins["FieldTypes"]:
            return True
        if typeName in self.model.builtins["PacketTypes"]:
            return True

        return False

    @staticmethod
    def _get_tag(element):
        return re.sub(r"{.*}", '', element.tag)

    def parse(self):
        self._parse_xml_schema()
        self._create_types()
        self._parse_node_ids()

    def _parse_xml_schema(self):
        self.xmlSchema = ElementTree.parse(self.schemaPath).getroot()

        for element in self.xmlSchema:
            elementType = self._get_tag(element)
            elementName = element.attrib.get("Name")

            if elementName is not None and not self._is_type_builtin(elementName):
                if elementType == "StructuredType":
                    self._parse_structured_type(element)
                elif elementType == "EnumeratedType":
                    self._parse_enum_type(element)
            else:
                if elementName is not None:
                    self.logger.debug("{} is builtinType!".format(elementName))

    def _parse_node_ids(self):
        with open(self.nodeIdsPath) as nodeIdsFile:
            reader = csv.reader(nodeIdsFile)

            for row in reader:
                if row[0].endswith("_Encoding_DefaultBinary"):
                    typeName = row[0].split("_")[0]
                    encodingId = row[1]
                    if typeName in self.model.classes:
                        self.model.nodeIdMappings[int(encodingId)] = self.model.classes[typeName]
                        self.model.classes[typeName].binaryEncodingId = int(encodingId)
                    else:
                        self.logger.warning(
                            "Type '{}' not found. Could not map NodeId '{}'".format(typeName, encodingId))

    def _parse_enum_type(self, element):
        enum = Enum()
        for k, v in element.items():
            if k == "Name":
                enum.name = v
            elif k == "LengthInBits":
                enum.lengthInBits = int(v)
            else:
                self.logger.warning("Unknown attr for enum: ", k)
        for el in element:
            tag = self._get_tag(el)
            if tag == "EnumeratedValue":
                ev = EnumValue()
                for k, v in el.attrib.items():
                    if k == "Name":
                        ev.name = v
                    elif k == "Value":
                        ev.value = v
                    else:
                        raise self.ParseError("Unknown field attrib: ", k)
                enum.values.append(ev)
            elif tag == "Documentation":
                enum.doc = el.text
            else:
                raise self.ParseError("Unknown enum tag: ", tag)

        self.model.enumTypes.append(enum)

    def _parse_structured_type(self, element):
        elementName = element.attrib.get("Name")
        newType = StructuredType(elementName)

        for el in element:
            tag = self._get_tag(el)
            if tag == "Field":
                newField = Field()
                for key, val in el.attrib.items():
                    if key == "Name":
                        newField.name = val
                    elif key == "TypeName":
                        newField.fieldType = re.sub(r".*:", "", val)
                    elif key == "LengthField":
                        for field in newType.fields:
                            if field.name == val:
                                field.lengthOf = newField
                                newField.lengthFrom = field
                    elif key == "SourceType":
                        # TODO: What to do with this? Ignore for now
                        pass
                        # print("SourceType: ", val)
                    else:
                        raise self.ParseError("{} keys are not supported in the current parser".format(key))

                newType.fields.append(newField)
            elif tag == "Documentation":
                newType.documentation = el.text
            else:
                self.logger.warning("Unknown tag: {}".format(tag))

        self.model.structuredTypes.append(newType)

    def _create_types(self):
        if self.xmlSchema is None:
            self.parse()

        self._create_enumerated_types()
        self._create_structured_types()
        pass

    def _create_enumerated_types(self):

        for eType in self.model.enumTypes:
            try:
                if eType.lengthInBits == 32:
                    typeString = "Enumeration"
                else:
                    typeString = "UInt" + str(eType.lengthInBits)

                self.model.enumFields[eType.name] = self.model.builtins["FieldTypes"][typeString]
            except KeyError:
                self.logger.warning("Error adding enumerated type '{}' Could not find "
                                    "builtinType with bit length {}".format(eType.name, eType.lengthInBits))

    def _create_structured_types(self):

        for sType in self.model.structuredTypes:
            self._create_structured_type(sType)

        lastLen = len(self.reparse)
        noProgress = 0
        while len(self.reparse) > 0:
            self._create_structured_type(self.reparse.pop(0))
            if lastLen == len(self.reparse):
                noProgress += 1
                if noProgress > 10:
                    self.logger.error("Exceeded maximum passes. Aborting types creation")
                    break
            lastLen = len(self.reparse)

        self.logger.debug("Done creating types")

    @staticmethod
    def _fill_field_args_dict(field):
        argsDict = {}
        if field.lengthOf is not None:
            if field.lengthInBytes:
                argsDict["length_of"] = field.lengthOf.name
            else:
                argsDict["count_of"] = field.lengthOf.name

        if field.lengthFrom is not None:
            if field.lengthFrom.lengthInBytes:
                argsDict["length_from"] = lambda p: getattr(p, field.lengthFrom.name)
            else:
                argsDict["count_from"] = lambda p: getattr(p, field.lengthFrom.name)

        return argsDict

    def _create_packet_type_field(self, name, cls, argsDict):
        if "count_from" in argsDict:
            field = PacketListField(name, None, cls, **argsDict)
        else:
            field = PacketField(name, cls(), cls)

        return field

    def _create_field_type_field(self, name, cls, argsDict):
        if "count_from" in argsDict:
            #field = cls(name, None)
            field = FieldListField(name, None, cls("", None), **argsDict)
        else:
            field = cls(name, None, **argsDict)

        return field

    def _create_structured_type(self, sType):
        try:
            fields_desc = []

            for field in sType.fields:
                argsDict = self._fill_field_args_dict(field)

                if field.fieldType in self.model.builtins["PacketTypes"]:
                    cls = self.model.builtins["PacketTypes"][field.fieldType]
                    fields_desc.append(self._create_packet_type_field(field.name, cls, argsDict))
                elif field.fieldType in self.model.builtins["FieldTypes"]:
                    cls = self.model.builtins["FieldTypes"][field.fieldType]
                    fields_desc.append(self._create_field_type_field(field.name, cls, argsDict))
                elif field.fieldType in self.model.enumFields:
                    cls = self.model.enumFields[field.fieldType]
                    fields_desc.append(cls(field.name, 0))
                else:
                    if field.fieldType in self.model.classes:
                        cls = self.model.classes[field.fieldType]
                        fields_desc.append(self._create_packet_type_field(field.name, cls, argsDict))
                    else:
                        self.reparse.append(sType)
                        self.logger.debug("Error adding type '{}' Could not find "
                                          "dependency. Re-queueing...".format(sType.name))
                        return

            newClass = type(sType.name, (UaTypePacket,), {"fields_desc": fields_desc, "binaryEncodingId": None})

            self.model.classes[sType.name] = newClass
        except KeyError:
            self.logger.warning("Unexpected error encountered while creating types. Types might be incomplete")

    def create_file(self, outputName):
        """
        Creates a file where the generated types are stored.
        This is an alternative if re-parsing the schema on every load
        is too inefficient.

        TODO: Implement

        :param outputName: The file name to write the types to.
        """
        pass
