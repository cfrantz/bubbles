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
# Author:
#    Chris Frantz
# 
# Description:
#    XML Schema processor
#
#####################################################
from bubbles.xmlimpl import ET
from bubbles.util import ns
from bubbles.dobject import DynamicObject
from bubbles.util.ordered_dict import OrderedDict
from bubbles.xsd.types import converter

import threading
import re
import urllib2 as u2
from urlparse import urljoin
from logging import getLogger
log=getLogger(__name__)

XSINIL = 1
PROPERTY = 2
ATTRIBUTE =4
CHOICE =   8
ANY =      16
QUALIFIED =32
xsi_type = ET.QName(ns.XSI, 'type')
xsi_nil = ET.QName(ns.XSI, 'nil')
xsi_nil_true = {xsi_nil: "true"}

class SchemaValidationError(Exception):
    pass

class _SchemaLoader:
    '''
    The SchemaLoader is a container for loading and pre-processing XML
    Schemas.
    '''
    def __init__(self):
        self.schemas = {}
        self.allns = {}

    def __call__(self):
        return _SchemaLoader()

    def load(self, schema, force=False, fragment=False, pathinfo='', basecls=None):
        '''
        Load and pre-process an XML schema.

        @type schema: L{ElementTree.Element} or URL
        @param schema: A schema to load.
        @type force: bool
        @param force: Optional.  Reload an already loaded schema.
        @type fragment: bool
        @param fragment: Optional.  The schema is actually a fragment of a
            an already-loaded schema and should be integrated with it.
        @type pathinfo: str
        @param pathinfo: Optional.  A URL to help with loading the schema.
            Usually used by SchemaLoader to process xs:import directives.
        @rtype: str
        @return: The targetNamespace of the loaded schema
        '''
        # Is schema already parsed 
        if ET.iselement(schema):
            root = schema
        else:
            schema = urljoin(pathinfo, schema)
            root = ET.parse(u2.urlopen(schema)).getroot()

        # Get the target namespace.  Exit early if we already know this schema.
        targetNamespace = root.get('targetNamespace')
        if targetNamespace in self.schemas and not (force or fragment):
            return targetNamespace

        # Add a new entry to our dictionary
        if not fragment:
            self.schemas[targetNamespace] = { 'root': root, 'types': {}, 'elements': {}, 'groups': {}, 'validator': None, 'basecls': basecls }

        # Update our "all namespaces" dictionary and get references to the
        # various subdictionaries we'll need
        self.allns.update(root.nsmap)
        types = self.schemas[targetNamespace]['types']
        elements = self.schemas[targetNamespace]['elements']
        groups = self.schemas[targetNamespace]['groups']

        # Process includes
        includes = []
        while True:
            # Get the list of includes
            inclist = root.findall(ns.expand('xs:include'))
            if not inclist:
                break

            for el in inclist:
                # remove it from the document
                root.remove(el)
                
                # Get the schemaLocation and compute the URL
                location = el.get('schemaLocation')
                if location in includes:
                    # skip if we've processed this schema
                    continue
                includes.append(location)
                url = urljoin(pathinfo, location)

                # Parse the XML and append it to the root document
                # We probably *should* include it into the place where the
                # xs:include node was, but for now, punt and append it
                # to the end of the document
                inc = ET.parse(u2.urlopen(url)).getroot()
                root.extend(inc)

        # Process imports
        for el in root.findall(ns.expand('xs:import')):
            location = el.get('schemaLocation')
            if location:
                self.load(location, pathinfo=pathinfo)
        # Find all first-level tags we care about and reference them
        # in the types/elements/groups dictionaries
        for el in root.findall(ns.expand('xs:complexType')):
            types[el.get('name')] = el
        for el in root.findall(ns.expand('xs:simpleType')):
            types[el.get('name')] = el
        for el in root.findall(ns.expand('xs:element')):
            elements[el.get('name')] = el
        for el in root.findall(ns.expand('xs:group')):
            groups[el.get('name')] = el

        # If this is a schema fragment, integrate it into the
        # original schema element tree in memory
        if fragment:
            realroot = self.schemas[targetNamespace]['root']
            nsmap = dict(realroot.nsmap)
            nsmap.update(root.nsmap)
            attrib = dict(realroot.attrib)
            attrib.update(root.attrib)
            newroot = ET.Element(realroot.tag, attrib=attrib, nsmap=nsmap)
            newroot.text = realroot.text

            newroot.extend(realroot.getchildren())
            newroot.extend(root.getchildren())
            self.schemas[targetNamespace]['root'] = newroot

        return targetNamespace

    def schema(self, namespace):
        '''Get the schema corresponding to namespace'''
        if '}' in namespace:
            (namespace, name) = ns.split(namespace)
        return self.schemas[namespace]['root']

    def type(self, name):
        '''Get the type corresponding to name'''
        (namespace, name) = ns.split(name)
        types = self.schemas[namespace]['types']
        return types.get(name)

    def element(self, name):
        '''Get the element corresponding to name'''
        (namespace, name) = ns.split(name)
        elements = self.schemas[namespace]['elements']
        return elements.get(name)

    def group(self, name):
        '''Get the group corresponding to name'''
        (namespace, name) = ns.split(name)
        groups = self.schemas[namespace]['groups']
        return groups[name]

    def basecls(self, name):
        '''Get the base class corresponding to name'''
        (namespace, name) = ns.split(name)
        cls = self.schemas[namespace]['basecls']
        return cls

    def validate(self, element, onerror='raise'):
        (namespace, name) = ns.split(element.tag)
        validator = self.schemas[namespace]['validator']
        if validator is None:
            validator = ET.XMLSchema(self.schemas[namespace]['root'])
            self.schemas[namespace]['validator'] = validator

        errlog = None
        if validator(element) == False:
            errlog = validator.error_log
            if onerror == 'log':
                log.error('Schema Validation Error: %s', errlog)
            elif onerror == 'pass':
                pass
            else:
                raise SchemaValidationError(errlog)
        return errlog




# Create a single global schemaloader.  Because of the __call__ method
# in _SchemaLoader, we can construct new SchemaLoaders by calling the
# single object:  ldr = SchemaLoader()
SchemaLoader = _SchemaLoader()

class SchemaObject(DynamicObject):
    '''
    Base class for complexTypes derived from XML schema
    '''
    __builder__ = None
    __template__ = ()
    __validate__ = False

    @classmethod
    def _template(cls):
        '''
        Examine the inheritance heirarchy of this class and
        construct the template.
        '''
        d = OrderedDict()
        for c in cls.__mro__[::-1]:
            for tmpl in getattr(c, '__template__', []):
                d[tmpl[0]] = tmpl
        return d.values()

    def _make_type(self, value, type):
        '''
        Parse value and convert it to type
        '''
        iselem = False
        if ET.iselement(value):
            iselem = True
            xtype = value.get(xsi_type)
            if xtype:
                xtype = ns.expand(xtype, value.nsmap)
                (prefix, t) = ns.split(xtype)
                if prefix == ns.XS:
                    type = 'xs:'+t
                else:
                    type = xtype
            if value.get(xsi_nil) == 'true':
                return None

        if type.startswith('xs:'):
            if iselem:
                value = value.text
            c = converter(type)
            if value is not None and not c.check(value):
                value = c.fromstr(value)
        else:
            if value == "":
                value = None
            value = self.__builder__.factory(type)(value, __relax__=self.__relax__)
        return value

    def __fromiter__(self, items):
        extra = False
        if not isinstance(items, dict):
            items = OrderedDict(items)

        # Iterate over the template and construct the object from
        # the template description
        for (name, type, default, minmax, flags) in self.__template__:
            # If this node is an "xs:any" node, note it for later and skip
            if flags & ANY:
                extra = True
                continue
            # I don't remember why I'm doing this
            if name in self:
                continue
            # Get the value out of the items dictionary, or use the
            # default if it doesn't exist
            value = items.pop(name, default)

            # If there is not value, but this is a choice element, skip
            if value is None and (flags & CHOICE):
                continue

            if minmax == (0,1):
                # Optional element
                # If we have a value, create the type
                if value is not None:
                    value = self._make_type(value, type)
            elif minmax == (1,1):
                # Manditory element
                value = self._make_type(value, type)
            else:
                # List of elements
                if value is None:
                    value = []
                if not isinstance(value, (list, tuple)):
                    if self.__relax__:
                        value = []
                    else:
                        raise TypeError('Field must be a list', name)
                value = [self._make_type(v, type) for v in value]
            self[name] = value

        # If this type has an xs:any node, set all the remaining items
        # using the base class.
        if extra:
            DynamicObject.__fromiter__(self, items)

    def __fromxml__(self, elem):
        if self.__validate__:
            self.__builder__.loader.validate(elem, self.__validate__)

        lat = len(self.__attrchar__)
        extra = False
        # Iterate over the template and construct the object from
        # the template descriptions
        for (name, type, default, minmax, flags) in self.__template__:
            # If this node is an "xs:any" node, note it for later and skip
            if flags & ANY:
                extra = True
                continue
            # I don't remember why I'm doing this
            if name in self:
                continue
            if (flags & ATTRIBUTE):
                # If this node is an attribute, get the value from the element attrs
                value = [elem.get(self.__nsx__(name[lat:], flags & QUALIFIED), default)]
            elif (flags & PROPERTY):
                # If its a property, get the value from the element text
                value = [elem.text]
            else:
                # Otherwise, find all XML elements with the field name
                value = elem.findall(self.__nsx__(name))

            # If there is no value list, but this is an xs:choice node, skip
            if len(value) == 0 and (flags & CHOICE):
                continue
            if minmax == (0,1) or minmax == (1,1):
                # The field is a single value
                l = len(value)
                if l == 0:
                    value = default
                elif l == 1:
                    value = value[0]
                else:
                    if self.__relax__:
                        value = value[0]
                    else:
                        raise TypeError('Expecting exactly 0 or 1 items', name)
                # If the value is present in the XML, or is required
                # by the template
                if value is not None or minmax[0] == 1:
                    value = self._make_type(value, type)
            else:
                # The field is a list
                value = [self._make_type(v, type) for v in value]
            self[name] = value

        # If there are xs:any items, fall back to the schemaless unmarshaller
        # in the base class
        if extra:
            DynamicObject.__fromxml__(self, elem, ignore=self.__keylist__[:])

    def __xml__(self, tag=None, node=None, nsmap=None):
        lat = len(self.__attrchar__)
        done = []
        extra = False
        if tag is None:
            tag = self.__class__.__name__
        tag = self.__nsx__(tag)
        if node is None:
            node = ET.Element(tag, nsmap=nsmap)

        # Construct reverse namespace map for doing xsi:type
        rmap = dict((v,k) for k, v in node.nsmap.items() if k is not None)

        # Iterate over the template to construct the XML representation.
        for (name, type, default, minmax, flags) in self.__template__:
            # If this field is an "xs:any" node, note it for later and skip
            if (flags & ANY):
                extra = True
                continue
            # If the field is choice/optional and doesn't exist, skip it
            if ((flags & CHOICE) or minmax[0] == 0) and name not in self:
                continue
            # Get the value
            value = self[name]
            done.append(name)
            
            if value is None and minmax[0] == 0 and not (flags & XSINIL):
                # Skip fields that are none and don't have to exist, as long
                # as they aren't nillable
                continue
            elif (flags & ATTRIBUTE):
                # Handle attributes.  Skip attributes that are optional
                value = converter(type).tostr(value)
                if value is None:
                    value = ''
                if value is not None or minmax[0]:
                    node.set(self.__nsx__(name[lat:], flags & QUALIFIED), value)
                continue
            elif (flags & PROPERTY):
                # Property
                node.text = converter(type).tostr(value)
                continue

            qname = self.__nsx__(name)
            if not isinstance(value, (list, tuple)):
                value = [value]
            for v in value:
                if v is None and (flags & XSINIL):
                    # Nil node
                    n = ET.Element(qname, xsi_nil_true)
                    node.append(n)
                elif ET.iselement(v):
                    # User supplied XML Elements, so just add them
                    node.append(v)
                elif type.startswith('xs:'):
                    # Primitive type
                    n = ET.Element(qname)
                    n.text = converter(type).tostr(v)
                    node.append(n)
                elif isinstance(v, DynamicObject):
                    # Dynamic object or subclass, so marshall and append
                    n = v.__xml__(name)
                    if type != v.__class__.__name__:
                        (namespace, datatype) = ns.split(v.__class__.__name__)
                        n.set(xsi_type, '%s:%s' % (rmap[namespace], datatype))
                    node.append(n)
                elif v == '':
                    # Carry-over for dealing with SUDS bug
                    pass
                else:
                    if not self.__relax__:
                        raise TypeError('Unknown type', name, type)

        # If there was an xs:any node, fall back to the schemaless marshaller
        # in the base class
        if extra:
            DynamicObject.__xml__(self, tag, node, ignore=done)
        return node

class Enumeration(SchemaObject):
    pass

class Builder:
    '''
    A Builder examines XML schema and constructs python types from the
    schema description.
    '''
    attr_use = { 'optional': (0, 1), 'prohibited': (0, 0), 'required': (1, 1) }
    cache = {}

    def __init__(self, loader=SchemaLoader, namespace=None, basecls=None):
        '''
        Constructor for Builder
 
        @type loader: SchemaLoader
        @param loader: Optional.  The SchemaLoader holding the schemas of interest
        @type namespace: str
        @param namespace: Optional.  The default namespace used by this builder.
        '''
        self.loader = loader
        self.namespace = namespace
        self.lock = threading.Lock()
        # Undocumented feature: Extra bases may be added to the class
        # heirarchy on a per-builder basis
        self.bases = ()

        self.root = None
        self.typename = None
        self.template = []
        self.restriction = None
        self.extension = None
        self.minOccurs = 0
        self.maxOccurs = 1
        self.flags = 0
        self.basecls = basecls or SchemaObject

    def nsexpand(self, s, target=True):
        tns = {}
        if target:
            tns['targetNamespace'] = self.root.get('targetNamespace')
        return ns.expand(s, self.root.nsmap, **tns)

    def nssplit(self, s, target=True):
        tns = {}
        if target:
            tns['targetNamespace'] = self.root.get('targetNamespace')
        return ns.split(s, self.root.nsmap, **tns)

    def factory(self, typename):
        '''
        A factory for building classobjects from schema.

        @type typename: str
        @param typename: The type to create
        @rtype: class
        @return: The requested class
        '''
        with self.lock:
            return self._factory(typename)

    def _factory(self, typename, **kwargs):
        if 'targetNamespace' not in kwargs and self.namespace:
            kwargs['targetNamespace'] = self.namespace

        typename = ns.expand(typename, self.loader.allns, **kwargs)
        cls = None
        try:
            cls = self.cache[typename]
        except KeyError:
            oldroot = self.root
            self.root = self.loader.schema(typename)
            node = self.loader.type(typename)

            if node is None:
                node = self.loader.element(typename)
                if node is not None and 'type' in node.attrib:
                    cls = self._factory(node.get('type'))

            if node is not None and cls is None:
                self.process(node)
                cls = self.cache.get(typename)

            self.root = oldroot
        if cls is None:
            raise TypeError("Unknown Type", typename)
        return cls

    @staticmethod
    def tryint(value):
        try:
            value = int(value)
        except ValueError:
            pass
        return value

    def push(self):
        state= (self.typename, self.template, self.extension, self.restriction, self.flags)
        self.typename = None
        self.template = []
        self.extension = self.basecls
        self.restriction = None
        self.flags = 0
        return state

    def pop(self, state):
        (self.typename, self.template, self.extension, self.restriction, self.flags) = state


    def process(self, nodelist, **kwargs):
        if not isinstance(nodelist, list):
            nodelist = [nodelist]
        for node in nodelist:
            if node.tag == ET.Comment:
                continue
            (namespace, name) = self.nssplit(node.tag)
            if namespace != ns.XS:
                raise Exception("Can only process nodes in xs namespace")
            pfunc = getattr(self, 'xs_'+name)
            if pfunc:
                pfunc(node, **kwargs)
            else:
                log.error("Don't know how to handle %s", name)

    def xs_attribute(self, node, **kwargs):
        ref = node.get('ref')
        if ref:
            log.debug("'ref' not supported in attributes yet")
            return
        
        name = self.extension.__attrchar__ + node.get('name')

        type = node.get('type')
        (namespace, type) = self.nssplit(type)
        if namespace != ns.XS:
            raise TypeError("Attribute types must be xs:types", type)
        type = 'xs:%s' % type

        default = node.get('default')
        if not default:
            default = node.get('fixed')

        use = node.get('use', 'optional')
        use = self.attr_use[use]

        flags = self.flags | ATTRIBUTE
        if self.root.get('attributeFormDefault') == 'qualified':
            flags |= QUALIFIED
        self.template.append((name, type, default, use, flags))

    def xs_element(self, node, **kwargs):
        ref = node.get('ref')
        if ref is not None:
            node = self.loader.element(self.nsexpand(ref))

        name = node.get('name')
        type = node.get('type')
        if type is None:
            if self.typename:
                type = '%s_%s' % (self.typename, name)
            else:
                type = self.nsexpand(name)
            self.process(node.getchildren(), name=type)
        else:
            type = self.nsexpand(type, target=False)
            (namespace, type) = self.nssplit(type)
            if namespace == ns.XS:
                type = 'xs:%s' % type
            else:
                type = '{%s}%s' % (namespace, type)

        default = node.get('default')
        min = self.tryint(node.get('minOccurs', self.minOccurs))
        max = self.tryint(node.get('maxOccurs', self.maxOccurs))
        nil = int(converter('xs:boolean').fromstr(node.get('nillable', 'false')))
        self.template.append((name, type, default, (min, max), self.flags | nil))

    def xs_enumeration(self, node, **kwargs):
        value = node.get('value')
        name = re.sub('[^A-Za-z0-9_]', '_', value).upper()
        type = self.restriction
        self.extension = Enumeration
        self.template.append((name, type, value, (0, 1), False))

    def xs_sequence(self, node, **kwargs):
        minmax = (self.minOccurs, self.maxOccurs)
        self.minOccurs = node.get('minOccurs', 1)
        self.maxOccurs = node.get('maxOccurs', 1)
        self.process(node.getchildren(), **kwargs)
        (self.minOccurs, self.maxOccurs) = minmax

    def xs_all(self, node, **kwargs):
        minmax = (self.minOccurs, self.maxOccurs)
        self.minOccurs = 1
        self.maxOccurs = 1
        self.process(node.getchildren(), **kwargs)
        (self.minOccurs, self.maxOccurs) = minmax

    def xs_any(self, node, **kwargs):
        min = self.tryint(node.get('minOccurs', self.minOccurs))
        max = self.tryint(node.get('maxOccurs', self.maxOccurs))
        self.template.append(('#any', 'xs:any', None, (min, max), self.flags | ANY))

    def _xs_type(self, node, **kwargs):
        state = self.push()
        name = node.get('name')
        if name:
            name = self.nsexpand(name)
        else:
            name = kwargs.pop('name')
        self.typename = name

        # Check to see if the SchemaLoader thinks there should be a special
        # baseclass for this type
        basecls = self.loader.basecls(name)
        if basecls:
            self.extension = basecls

        self.process(node.getchildren(), **kwargs)
        cvars = {
            '__template__': self.template,
            '__namespace__': self.root.get('targetNamespace'),
            '__builder__': self,
        }
        bases = self.bases + (self.extension,)
        t = type(self.typename, bases, cvars)
        self.cache[self.typename] = t

        # Examine the template.  Replace enumerated types with the
        # type from which they are derived.
        for i in range(len(self.template)):
            clsname = self.template[i][1]
            if clsname.startswith('xs:'):
                continue
            cls = self._factory(clsname)
            if Enumeration in cls.__mro__:
                self.template[i] = (
                        self.template[i][0],
                        cls.__template__[0][1],
                        self.template[i][2],
                        self.template[i][3],
                        self.template[i][4])

        # Merge all templates from the class heirarchy
        t.__template__ = t._template()
        self.pop(state)

    def xs_complexType(self, node, **kwargs):
        return self._xs_type(node, **kwargs)

    def xs_complexContent(self, node, **kwargs):
        self.process(node.getchildren(), **kwargs)

    def xs_simpleType(self, node, **kwargs):
        return self._xs_type(node, **kwargs)

    def xs_simpleContent(self, node, **kwargs):
        self.process(node.getchildren(), **kwargs)

    def xs_choice(self, node, **kwargs):
        self.flags |= CHOICE
        self.process(node.getchildren(), **kwargs)
        self.flags &= ~CHOICE

    def xs_group(self, node, **kwargs):
        ref = node.get('ref')
        node = self.loader.group(self.nsexpand(ref))
        self.process(node.getchildren(), **kwargs)

    def xs_annotation(self, node, **kwargs):
        pass

    def xs_restriction(self, node, **kwargs):
        base = node.get('base')
        (namespace, type) = self.nssplit(base)
        if namespace != ns.XS:
            raise TypeError("Restriction types must be xs:types")
        self.restriction = 'xs:%s' % type
        self.process(node.getchildren(), **kwargs)

    def xs_extension(self, node, **kwargs):
        base = node.get('base')
        (namespace, type) = self.nssplit(base)
        if namespace == ns.XS:
            base = 'xs:'+type
            self.template.append(('value', base, None, (0, 1), self.flags | PROPERTY))
        else:
            cls = self._factory(base)
            if Enumeration in cls.__mro__:
                base = cls.__template__[0][1]
                self.template.append(('value', base, None, (0, 1), self.flags | PROPERTY))
            else:
                self.extension = cls
        self.process(node.getchildren(), **kwargs)

    def xs_minInclusive(self, node, **kwargs):
        pass
    def xs_maxInclusive(self, node, **kwargs):
        pass



# VIM options (place at end of file)
# vim: ts=4 sts=4 sw=4 expandtab:
