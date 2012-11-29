#!/usr/bin/env python
#####################################################
#
# copyright.txt
#
# Copyright 2012 Hewlett-Packard Development Company, L.P.
#
# Hewlett-Packard and the Hewlett-Packard logo are trademarks of
# Hewlett-Packard Development Company, L.P. in the U.S. and/or other countries.
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
#
#
# Author:
#    Chris Frantz
# 
# Description:
#    Silly helper program to try to auto-generate schemas from XML
#    documents.  I've tried to make this program fairly general, but
#    its current purpose is to help generate schemas for iLO's RIBCL
#    language.  There are a few iLO specific assumptions in this code.
#
#####################################################
from bubbles.xsd.schema import SchemaLoader, SchemaObject, Builder
from bubbles.dobject import DynamicObject
from bubbles.xmlimpl import ET
from bubbles.util import ns
from collections import OrderedDict
import sys
import json
import re
from getopt import getopt

# The MetaSchema is a Schema definition for creating Schemas
SchemaLoader.load("file:bubbles/misc/MetaSchema.xsd")
class MetaSchemaObject(SchemaObject):
    # Since schema documents are so attribute laden, using a
    # sigil like "_" to represent attributes will just be tedious and
    # confusing, so eliminate it
    __attrchar__ = ''

b = Builder(basecls=MetaSchemaObject)

# Get types from MetaSchema.xsd.  These types are a subset
# of the real XMLSchema
Element = b.factory('Element')
Attribute = b.factory('Attribute')
ComplexType = b.factory('ComplexType')
Choice = b.factory('Choice')
Schema = b.factory('Schema')
All = b.factory('All')
Sequence = b.factory('Sequence')
SimpleContent = b.factory('SimpleContent')
Extension = b.factory('Extension')

# There is a non-standard element called "path" used by complexTypes
# to figure out their uniqueness.  In order for schema merging to work
# across multiple runs, we need to preserve this information.
PATH = '{urn:nonstd}path'


class AutoSchema:
    def __init__(self, tns):
        self.schema = Schema(targetNamespace=tns, elementFormDefault='qualified')
        self.typeinfo = {"attributes":{}, "elements":{}}

    def merge(self, filename):
        # We change the namespace of XMLSchema to something else because
        # the schema processor in the bubbles library can't operate on the
        # XS namespace.  Hack...
        doc = file(filename).read()
        doc = doc.replace(ns.XS, 'urn:metaschema')
        xsd = ET.fromstring(doc)
        self.schema = Schema(xsd)

    def guess(self, filename):
        text = file(filename).read()
        text = re.sub(r'xmlns="[^"]*"', '', text)
        xml = ET.fromstring(text)
        obj = DynamicObject(xml)
        tns, tag = ns.split(xml.tag)
        root = self.complexType(tag, obj)
        el = Element(name=tag, type=root.name)
        self._addElement(self.schema, el)

    def output(self):
        # Since the MetaSchema isn't in the XMLSchema namespace (but it's
        # meant to be, except for the aforementioned limitiaion in bubbles),
        # we use a different namespace and then just change the namespace
        # after the fact.
        namespaces = {
            'xs': 'urn:metaschema',
            'nonstd': 'urn:nonstd',
            None: self.schema.targetNamespace
        }
        s = self.schema.__xmlstr__(tag='schema', nsmap=namespaces)
        s = s.replace('urn:metaschema', ns.XS)
        return s

    def load_typeinfo(self, filename):
        self.typeinfo.update(json.load(file(filename)))

    def primitive(self, name, *attrs):
        ct = ComplexType(name=name)
        for attr, type in attrs:
            ct.attribute.append(Attribute(name=attr, type=type))
        self.schema.complexType.append(ct)

    def ilo_primitives(self):
        # iLO uses lots of attributes in it's schema documents.  While
        # defining this many primitve types isn't strictly necessary,
        # it does make the resulting schema a bit easier to understand
        self.primitive('BooleanValue', ('VALUE', 'xs:string'))
        self.primitive('IntegerValue', ('VALUE', 'xs:string'))
        self.primitive('IpAddressValue', ('VALUE', 'xs:string'))
        self.primitive('MacAddressValue', ('VALUE', 'xs:string'))
        self.primitive('StringValue', ('VALUE', 'xs:string'))
        self.primitive('StatusValue', ('STATUS', 'xs:string'))
        self.primitive('UnitValue', ('VALUE', 'xs:string'), ('UNIT', 'xs:string'))
        self.primitive('RouteValue', ('DEST', 'xs:string'), ('MASK', 'xs:string'), ('GATEWAY', 'xs:string'))

        # This special type is for the PCAP member of Get_Pwreg.  So far,
        # this is the only item in the iLO data that has simple text
        # content and attributes.
        pcap = ComplexType(name="Pcap")
        pcap.simpleContent = SimpleContent(
                extension=Extension(base="xs:string"))
        pcap.simpleContent.extension.attribute.append(
                Attribute(name="MODE", type="xs:string"))
        self.schema.complexType.append(pcap)

    @staticmethod
    def checkvalue(val):
        if val.isdigit():
            return 'IntegerValue'
        if re.match('[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', val):
            return 'IpAddressValue'
        if re.match('[0-9A-F]{2}[:-][0-9A-F]{2}[:-][0-9A-F]{2}[:-][0-9A-F]{2}[:-][0-9A-F]{2}[:-][0-9A-F]{2}', val, re.I):
            return 'MacAddressValue'
        if val in ('Y', 'N'):
            return 'BooleanValue'
        return 'StringValue'

    @staticmethod
    def checktype(node):
        if len(node)==1:
            if '_VALUE' in node:
                return AutoSchema.checkvalue(node._VALUE)
            if '_STATUS' in node:
                return 'StatusValue'
        if len(node)==2:
            if '_VALUE' in node and '_UNIT' in node:
                return 'UnitValue'
        if len(node)>=2:
            if '_DEST' in node and '_GATEWAY' in node:
                return 'RouteValue'
        return None

    @staticmethod
    def typename(tag):
        tt = tag.split('_')
        # Remove all digit fields from the typename
        tt = [x for x in tt if not x.isdigit()]
        tt = map(str.capitalize, tt)
        tt = '_'.join(tt)
        return tt

    def addElement(self, ct, el, seq='sequence'):
        p = ct[PATH] or ''
        fullname = '/'.join((p, ct.name, el.name))
        attrs = self.typeinfo['elements'].get(fullname, {})
        for k, v in attrs.items():
            setattr(el, k, v)
        self._addElement(ct[seq], el, fullname)

    def _addElement(self, seq, el, fullname=None):
        for i in range(len(seq.element)):
            # Possibly replace the element if we already have one
            # with the same name
            a = seq.element[i]
            if a.name == el.name:
                a = (a.minOccurs, a.maxOccurs)
                b = (el.minOccurs, el.maxOccurs)
                # The "greater" version of min/max is the one we want
                if b>a:
                    seq.element[i] = el
                break
        else:
            # If the for loop didn't exit via break
            index = -1
            if fullname:
                index = self.typeinfo['positions'].get(fullname, -1)
            if index >= 0 and index < len(seq):
                seq.element.insert(index, el)
            else:
                seq.element.append(el)

    def addAttribute(self, ct, name, type):
        p = ct[PATH] or ''
        at = Attribute(name=name, type=type)
        fullname = '/'.join((p, ct.name, at.name))
        attrs = self.typeinfo['attributes'].get(fullname, {})
        for k, v in attrs.items():
            setattr(at, k, v)

        for i in range(len(ct.attribute)):
            # Replace the attribute if we already have it
            if ct.attribute[i].name == at.name:
                ct.attribute[i] = at
                break
        else:
            # If the for loop didn't exit via break
            ct.attribute.append(at)

    def complexType(self, tag, node, parent=[]):
        tt = self.typename(tag)
        # Keep "Root" out of the pathname
        path = '/'.join(parent[1:])
        types = dict((t.name, t) for t in self.schema.complexType)
        newtype = False
        if tt in types:
            # Heuristic: if the node in complextypes has the same path as
            # the node being examined, they're the same type.  If not, then
            # create a new name
            ct = types[tt]
            if ct[PATH] != path:
                pp = parent[-1]
                # Abbreiviate using the first letter of each word in the
                # immediate parent node
                # e.g. Get_Embbedded_Health_Data -> GEHD
                pp = ''.join(p[0] for p in pp.split('_'))
                tt = "%s_%s" % (pp, tt)
                if tt in types:
                    ct = types[tt]
                else:
                    newtype = True
        else:
            newtype = True

        cttype = None
        if newtype:
            ct = ComplexType(name = tt)
            ct[PATH] = path
            fullname = '/'.join((path, ct.name))
            ctinfo = self.typeinfo['types'].get(fullname, {})
            for k, v in ctinfo.items():
                if k == 'complexType':
                    if v == 'all':
                        cttype = v
                        ct.all = All()
                    elif v == 'choice':
                        cttype = v
                        ct.choice = Choice()
                    break
            if not ct.all and not ct.choice:
                ct.sequence = Sequence()
                cttype = 'sequence'
        else:
            if ct.all:
                cttype = 'all'
            elif ct.choice:
                cttype = 'choice'
            else:
                cttype = 'sequence'
        # Normally, we want children of ComplexTypes to be part of a
        # Sequence.  For the ilo RIBCL node, they should be part of a
        # Choice node.
        #if tt == 'Ribcl' and newtype:
        #    ct.choice = Choice()

        parent = parent + [tt]
        #print >>sys.stderr, "Handling ", path, tag, node
        for k,v in node:
            if k.startswith('_'):
                self.addAttribute(ct, k[1:], 'xs:string')
                continue

            if isinstance(v, list):
                # Will not detect lists of primitive types
                for vv in v:
                    if isinstance(vv, DynamicObject):
                        t = self.checktype(v)
                        if t:
                            el = Element(name=k, type=t)
                        else:
                            vv = self.complexType(k, vv, parent)
                            el = Element(name=k, type=vv.name)
                    else:
                        el = Element(name=k, type='xs:string')
                    el.minOccurs=0
                    el.maxOccurs="unbounded"
            elif isinstance(v, DynamicObject):
                t = self.checktype(v)
                if t:
                    el = Element(name=k, type=t)
                else:
                    v = self.complexType(k, v, parent)
                    el = Element(name=k, type=v.name)
            else:
                el = Element(name=k, type='xs:string')

            if tag == 'RIBCL' and el.name != 'RESPONSE':
                el.minOccurs = 0
                el.maxOccurs = 1
            
            self.addElement(ct, el, cttype)

        if newtype:
            self.schema.complexType.append(ct)
        return ct

def usage(prog):
    print """Usage: %s [-o filename] [xmlfiles]...

Examine XML and guess an XSD schema for it.

    -m <filename>: Read the schema in filename and merge the guesswork with it.
    -n <namespace>: Set the targetNamespace.
    -o <filename>: Write the schema to filename (default stdout)
    -t <filename>: Load type hints from filename.
""" % prog
    return 1

def main(argv):
    opts = getopt(argv[1:], 'm:n:o:t:h?')
    ofile = None
    merge = None
    typeinfo = None
    tns = 'urn:xxx'
    for (opt, val) in opts[0]:
        if opt == '-m':
            merge = val
        elif opt == '-n':
            tns = val
        elif opt == '-o':
            ofile = val
        elif opt == '-t':
            typeinfo = val
        elif opt in ('-h', '-?'):
            return usage(argv[0])
        else:
            print "Unknown option:", opt
            return usage(argv[0])

    a = AutoSchema(tns)
    a.ilo_primitives()
    if merge:
        a.merge(merge)

    if typeinfo:
        a.load_typeinfo(typeinfo)

    for xmlfile in opts[1]:
        a.guess(xmlfile)

    if ofile:
        ofile = file(ofile, 'w')
    else:
        ofile = sys.stdout
    print >>ofile, a.output()
    return 0

if __name__ == '__main__':
    sys.exit(main(sys.argv))

# vim: ts=4 sts=4 sw=4 expandtab:
