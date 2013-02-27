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
#
#####################################################

from bubbles.xmlimpl import ET

def _ind(i):
    return i*4

# DynamicObject is a base class for Dynamic XML and JSON objects.
# DynamicObject can be initialized via iterables like dicts and lists,
# an XML Element or from kwargs.
# DynamicObject knows how to serialize itself to XML and provides
# Attribute, Dict-like and Array-like access to it's members.
#
# Attributes that start with __attrchar__ represent XML attributes
# If the value of __property__ is set, then that field makes the
# DynamicObject behave like a property object.
#   
# Property Object can be created with the constructor as well:
#   x = DynamicObject("yahoo", _a=50, _b=100)
#
#   Serializes to:    <tagname a="50" b="100">yahoo</tagname>

class DynamicObject(object):
    __namespace__ = None
    __property__ = None
    #__attrchar__ = '@'
    __attrchar__ = '_'

    def __nsx__(self, s, expand=True):
        '''
        Expand s in this object's namespace

        @type s: str
        @param s: string to expand
        @rtype: str
        @return: Expanded string
        '''
        if '}' in s:
            return s
        if expand and self.__namespace__:
            s = '{%s}%s' % (self.__namespace__, s)
        return s

    def __fromiter__(self, items):
        '''
        Set fields in the object from an iterable

        @type items: iterable
        @param items: The items to set.  The iterable should be a dictionary,
            a list of (key, value) tuples or an object that yields (k,v) pairs
            when iterated.
        '''
        if isinstance(items, dict):
            items = items.items()
        for k,v in items:
            if isinstance(v, dict) and getattr(v, 'listlike', False):
                # A dict with integer keys (objectpath: foo.bar.7.baz='hello')
                # Unfortunately, this won't handle list-of-list or empty lists
                v2 = []
                for x in v:
                    if isinstance(x, dict):
                        x = DynamicObject(x)
                    v2.append(x)
                v = v2
            elif isinstance(v, dict):
                # Translate sub-dictionaries into DynamicObject
                v = DynamicObject(v)
            elif isinstance(v, list):
                # Iterate over list object, detect and translate dicts
                v2 = []
                for x in v:
                    if isinstance(x, dict):
                        x = DynamicObject(x)
                    v2.append(x)
                v = v2
            self[k] = v

    def __fromxml__(self, elem, ignore=[]):
        '''
        Set fields in the object from an XML element.

        @type elem: L{ElementTree.Element}
        @param elem: The XML element
        @type ignore: list
        @param ignore: XML tags/attributes to ignore

        This method will iterate over the element's children and build
        sub child objects for each child node.
        '''
        # First add the element attributes.  Prepend attributes with
        # __attrchar__
        at = self.__attrchar__
        for k,v in elem.attrib.items():
            k = at+k
            if k not in ignore:
                self[k] = v

        if len(elem):
            # Examine the children of elem
            for child in elem.getchildren():
                # ignore comments
                if child.tag == ET.Comment:
                    continue
                
                # Discard namespace
                tag = child.tag.split('}')[-1]
                if tag in ignore:
                    continue

                # If the child elment has children or attributes,
                # build a DynamicObject for it, otherwise, use its text
                if len(child) or child.attrib:
                    cval = DynamicObject(child)
                else:
                    cval = child.text

                # Check if we already have a field with this name.
                # If not, its just a value.  Otherwise, turn the value
                # into a list.
                val = getattr(self, tag, None)
                if val is None:
                    self[tag] = cval
                elif isinstance(val, list):
                    val.append(cval)
                else:
                    self[tag] = [val, cval]
        elif elem.text is not None:
            # If there were no children, then this is a "property" object.
            self.__property__ = 'value'
            self['value'] = elem.text

    def __init__(self, *args, **kwargs):
        '''
        DynamicObject Constructor.

        @param args: Positional/un-named arguments or iterables.
        @param kwargs: Keyword arguments

        There are several ways to construct a new DynamicObject:

            a = DynamicObject() -- Build an empty object
            b = DynmaicObject("baz", _foo="bar") -- Build a "property" object.
            c = DynamicObject(b) -- Build a copy of "b"
            d = DynamicObject(a=1,b=2,c="foo") -- Build an object from keyword args
            e = DynamicObject(some_dict) -- Build an object from dict
            f = DynamicObject([(key, value), (key, value)]) -- Build an object from list
            g = DynamicObject(some_elementtree_elment) -- Build an object from XML
        '''
        # This bit of code is really for SchemaObject, but we can
        # just put it here so we don't have to write a special constructor
        # for SchemaObject.
        validate = kwargs.pop('__validate__', None)
        if validate is not None:
            self.__validate__ = validate
        self.__relax__ = kwargs.pop('__relax__', False)

        self.__keylist__ = []
        for arg in args:
            if isinstance(arg, (dict, list, DynamicObject)):
                self.__fromiter__(arg)
            elif ET.iselement(arg):
                self.__fromxml__(arg)
            elif arg is None:
                pass
            else:
                self.__property__ = 'value'
                # Pass it to __fromiter__ so if this is a SchemaObject,
                # the value can be consumed by _make_type.
                self.__fromiter__({'value': arg})
        self.__fromiter__(kwargs.items())

    def __setattr__(self, name, value):
        if not (name.startswith('__') and name.endswith('__')) and \
                name not in self.__keylist__:
            self.__keylist__.append(name)
        self.__dict__[name] = value

    def __delattr__(self, name):
        try:
            del self.__dict__[name]
            if not (name.startswith('__') and name.endswith('__')):
                self.__keylist__.remove(name)
        except:
            clsname = self.__class__.__name__
            raise AttributeError("%s has no attribute '%s'" % (clsname, name))

    def __getitem__(self, name):
        if isinstance(name, int):
            name = self.__keylist__[name]
        try:
            return getattr(self, name)
        except AttributeError:
            raise KeyError(name)


    def __setitem__(self, name, value):
        setattr(self, name, value)

    def __delitem__(self, name):
        if isinstance(name, int):
            name = self.__keylist__[name]
        try:
            return delattr(self, name)
        except:
            raise KeyError(name)

    def __iter__(self):
        for k in self.__keylist__:
            yield (k, self[k])

    def __len__(self):
        return len(self.__keylist__)

    def __contains__(self, name):
        return name in self.__keylist__

    def __print__(self, value=None, out=None, indent=0):
        '''
        Print a human readable representation of an object.

        Used by __repr__.
        '''
        if isinstance(value, DynamicObject):
            out.append('%s(' % value.__class__.__name__)
            if len(value):
                out.append('\n')
            else:
                indent=0
            for (k, v) in value:
                out.append('%*s%s=' % (_ind(indent+1), '', k))
                self.__print__(v, out, indent+1)
                out.append(',\n')
            out.append('%*s)' % (_ind(indent), ''))
        elif isinstance(value, (list, tuple)):
            ch = '[]' if isinstance(value, list) else '()'
            out.append(ch[0])
            if len(value):
                out.append('\n')
            else:
                indent=0
            for v in value:
                out.append('%*s' % (_ind(indent+1), ''))
                self.__print__(v, out, indent+1)
                out.append(',\n')
            out.append('%*s%s' % (_ind(indent), '', ch[1]))
        elif isinstance(value, dict):
            out.append('{')
            if len(value):
                out.append('\n')
            else:
                indent=0
            for k, v in value.items():
                out.append('%*s%s: ' % (_ind(indent+1), '', repr(k)))
                self.__print__(v, out, indent+1)
                out.append(',\n')
            out.append('%*s}' % (_ind(indent), ''))
        else:
            out.append(repr(value))

        return out

    def __xml__(self, tag=None, node=None, nsmap=None, ignore=[]):
        '''
        Convert a DynamicObject to XML elements

        @type tag: str
        @param tag: Optional.  The name of the tag of the root node.
        @type node: L{ElementTree.Element}
        @param node: Optional.  A root node to populate.
        @type nsmap: dict
        @param nsmap: Optional.  A dictionary of namespace prefixes and namespaces to use.
        @type ignore: list
        @param ignore: Optional.  A list of fields to ignore during serialization to XML.
        @rtype: L{ElementTree.Element}
        @return: An XML Element representing this object.
        '''
        at = self.__attrchar__
        prop = self.__property__
        if tag is None:
            tag = self.__class__.__name__
        tag = self.__nsx__(tag)
        if node is None:
            node = ET.Element(tag, nsmap=nsmap)

        for key, value in self:
            if key in ignore:
                continue
            if key[0] == at:
                node.set(key[1:], unicode(value))
                continue
            name = self.__nsx__(key)
            if key == prop:
                node.text = unicode(value)
                continue
            if not isinstance(value, (list, tuple)):
                value = [value]
            for v in value:
                if isinstance(v, DynamicObject):
                    node.append(v.__xml__(key))
                elif ET.iselement(v):
                    node.append(v)
                else:
                    n = ET.Element(name)
                    if v is not None:
                        n.text = unicode(v)
                    node.append(n)
        return node

    def __xmlstr__(self, tag=None, node=None, nsmap=None):
        '''
        Convert a DynamicObject a string containing the XML representation.

        See __xml__ for an explaination of the arguments.
        '''
        return ET.tostring(self.__xml__(tag, node, nsmap), pretty_print=True)

    def __clear__(self):
        '''
        Delete all fields in this object.
        '''
        for k in self.__keylist__[:]:
            delattr(self, k)

    def __asdict__(self):
        return dict(self, __classname__=self.__class__.__name__)

    def __repr__(self):
        return ''.join(self.__print__(self, []))

# VIM options (place at end of file)
# vim: ts=4 sts=4 sw=4 expandtab:
