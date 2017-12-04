# coding=utf-8

import xml.etree.ElementTree as ElementTree
import sys
import re
from scapy.contrib.opcua.helpers import UaTypePacket
from scapy.fields import PacketField


class Field(object):

    def __init__(self):
        self.name = None
        self.fieldType = None
        self.lengthOf = None

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
        self.enumFields = {}


class SchemaParser(object):

    class ParseError(Exception):
        pass

    def __init__(self, schemaPath="./schema/Opc.Ua.Types.bsd", builtins=None):
        """

        :param schemaPath: Path to the schema .bsd file
        :param builtins: A dict of builtins where the PacketTypes element is a dict of builtin Packet types and the
                         FieldTypes element a dict of builtin Field types. Each dict should contain a string identifier
                         and the associated class. If nothing is passed, the types are inferred from the
                         builtinTypes.py module.
        """
        self.schemaPath = schemaPath
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
        self.xmlSchema = ElementTree.parse(self.schemaPath).getroot()

        for element in self.xmlSchema:
            elementType = self._get_tag(element)
            elementName = element.attrib.get("Name")

            if elementName is not None and not self._is_type_builtin(elementName):
                if elementType == "StructuredType":
                    self.parse_structured_type(element)
                elif elementType == "EnumeratedType":
                    self.parse_enum_type(element)
            else:
                if elementName is not None:
                    print("{} is builtinType!".format(elementName))

    def parse_enum_type(self, element):
        enum = Enum()
        for k, v in element.items():
            if k == "Name":
                enum.name = v
            elif k == "LengthInBits":
                enum.lengthInBits = int(v)
            else:
                print("Unknown attr for enum: ", k)
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

    def parse_structured_type(self, element):
        elementName = element.attrib.get("Name")
        newType = StructuredType(elementName)
        """
        for key, val in element.attrib.items():
            if key == "Name":
                print("Name: ", val)
            elif key == "BaseType":
                if ":" in val:
                    prefix, val = val.split(":")
                print("BaseType: ", val)
                tmp = struct
                while tmp.basetype:
                    struct.parents.append(tmp.basetype)
                    tmp = self.model.get_struct(tmp.basetype)
            else:
                print("Error unknown key: ", key)
        """
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
                print("Unknown tag: ", tag)

        self.model.structuredTypes.append(newType)

    def create_types(self):
        if self.xmlSchema is None:
            self.parse()

        self.create_enumerated_types()
        self.create_structured_types()
        pass

    def create_enumerated_types(self):

        for eType in self.model.enumTypes:
            try:
                if eType.lengthInBits == 32:
                    typeString = "Enumeration"
                else:
                    typeString = "UInt" + str(eType.lengthInBits)

                self.model.enumFields[eType.name] = self.model.builtins["FieldTypes"][typeString]
            except KeyError:
                print("Error adding enumerated type '", eType.name, "' Could not find builtinType with bit length ",
                      eType.lengthInBits)

    def create_structured_types(self):

        for sType in self.model.structuredTypes:
            self._create_structured_type(sType)

        lastLen = len(self.reparse)
        noProgress = 0
        while len(self.reparse) > 0:
            self._create_structured_type(self.reparse.pop(0))
            if lastLen == len(self.reparse):
                noProgress += 1
                if noProgress > 10:
                    print("Exceeded maximum passes. Aborting types creation")
                    break
            lastLen = len(self.reparse)

        print("Done creating types")

    def _create_structured_type(self, sType):
        try:
            fields_desc = []

            for field in sType.fields:
                if field.fieldType in self.model.builtins["PacketTypes"]:
                    cls = self.model.builtins["PacketTypes"][field.fieldType]
                    fields_desc.append(PacketField(field.name, cls(), cls))
                elif field.fieldType in self.model.builtins["FieldTypes"]:
                    cls = self.model.builtins["FieldTypes"][field.fieldType]
                    fields_desc.append(cls(field.name, None))
                elif field.fieldType in self.model.enumFields:
                    cls = self.model.enumFields[field.fieldType]
                    fields_desc.append(cls(field.name, 0))
                else:
                    cls = self.model.classes[field.fieldType]
                    fields_desc.append(PacketField(field.name, cls(), cls))
            newClass = type(sType.name, (UaTypePacket,), {"fields_desc": fields_desc})

            self.model.classes[sType.name] = newClass
        except KeyError:
            self.reparse.append(sType)
            print("Error adding type '", sType.name, "' Could not find dependency. Re-queueing...")

    def create_file(self, outputName):
        """
        Creates a file where the generated types are stored.
        This is an alternative if re-parsing the schema on every load
        is too inefficient.

        TODO: Implement

        :param outputName: The file name to write the types to.
        """
        pass


def _populate_module(model):
    print("Populating module...")
    for name, cls in model.classes.items():
        setattr(sys.modules[__name__], "Ua" + name, cls)


_parser = SchemaParser()
_parser.create_types()
_populate_module(_parser.model)
