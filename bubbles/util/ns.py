#####################################################
#
# ns.py
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
#    XML namespace utility functions
#
#####################################################


XS = 'http://www.w3.org/2001/XMLSchema'
XSI = 'http://www.w3.org/2001/XMLSchema-instance'
WSDL = 'http://schemas.xmlsoap.org/wsdl/'
SOAP = 'http://schemas.xmlsoap.org/wsdl/soap12/'
MIME = 'http://schemas.xmlsoap.org/wsdl/mime'
WSSE = "http://schemas.xmlsoap.org/ws/2002/07/secext"
WSU = "http://schemas.xmlsoap.org/ws/2002/07/utility"
SOAPENV = "http://schemas.xmlsoap.org/soap/envelope/"
SOAPENC = "http://schemas.xmlsoap.org/soap/encoding/"

_defns = {
        'xs': XS,
        'xsi': XSI,
        'wsdl': WSDL,
        'soap': SOAP,
        'mime': MIME,
        'wsse': WSSE,
        'wsu': WSU,
        'soapenv': SOAPENV,
        'soapenc': SOAPENC,
}

class UnknownNamespace(Exception):
    pass

def expand(s, nsmap={}, **kwargs):
    '''
    Expand a string with a namespace.

    @type s: str
    @param s: String to expand
    @type nsmap: dict
    @param nsmap: Optional. Dictionary of prefixes and namespaces.
    @param kwargs: Extra namespaces.

    The string may be of one of the following forms:

        {foo}bar -- String contains a namespace.  Do nothing.
        blah -- Expand to {targetNamespace}blah or {None-namespace}blah if they exist.
        xs:int -- Expand the namespace prefix: {http://www.w3.org/2001/XMLSchema}int
        a:x/b:y -- Expand each of the components: {URI-a}x/{URI-b}y
        */a:x/b:y -- Expand each of the components: */{URI-a}x/{URI-b}y

    Note: This function won't work for XPath like strings with attributes that may be
    in a namespace:  //foo:bar[@name="bleep:bloop"].  Sorry.
    '''
    if '}' in s:
        return s

    if '/' in s:
        ret = []
        for segment in s.split('/'):
            if segment and segment != '*':
                segment = expand(segment, nsmap, **kwargs)
            ret.append(segment)
        return '/'.join(ret)

    if not nsmap:
        nsmap=_defns
    kwargs.update(nsmap)
    if ':' in s:
        (ns, val) = s.split(':')
        try:
            ns = kwargs[ns]
        except KeyError:
            raise UnknownNamespace(ns)
    else:
        val = s
        if 'targetNamespace' in kwargs:
            ns = kwargs['targetNamespace']
        elif None in kwargs:
            ns = kwargs[None]
        else:
            raise UnknownNamespace('No target namespace')

    return '{%s}%s' % (ns, val)


def split(s, nsmap={}, **kwargs):
    '''
    Expand a string with a namespace.

    @type s: str
    @param s: String to expand
    @type nsmap: dict
    @param nsmap: Optional. Dictionary of prefixes and namespaces.
    @param kwargs: Extra namespaces.

    This does the inverse of expand.  Returns a 2-tuple of namespace-URI and tag.
    '''
    if '}' in s:
        (ns, tag) = s.split('}')
        ns = ns[1:]
        return (ns, tag)

    if not nsmap:
        nsmap = _defns
    kwargs.update(nsmap)
    if ':' in s:
        (ns, tag) = s.split(':')
        try:
            ns = kwargs[ns]
        except KeyError:
            raise UnknownNamespace(ns)
    else:
        tag = s
        ns = kwargs.get('targetNamespace')
        if ns is None:
            ns = kwargs.get(None)
    return (ns, tag)


# VIM options (place at end of file)
# vim: ts=4 sts=4 sw=4 expandtab:
