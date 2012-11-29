#####################################################
#
# client.py
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
from bubbles.xmlimpl import ET, xmlstr
from bubbles.util import ns
from bubbles.xsd.schema import SchemaLoader, Builder
from bubbles.dobject import DynamicObject
from copy import copy
import urllib2 as urllib2
from urlparse import urljoin
from logging import getLogger
import socket

log = getLogger(__name__)

class SoapFault(DynamicObject, Exception):
    '''
    SoapFault holds SOAP-ENV:Fault messages as exceptions.
    '''
    def __init__(self, faultxml=[], client=None):
        DynamicObject.__init__(self)
        Exception.__init__(self)

        self.code = None
        self.message = None
        self.detail = None

        for node in faultxml:
            tag = node.tag.split('}')[-1]
            if tag == 'faultcode':
                self.code = ns.split(node.text, nsmap=faultxml.nsmap)
            elif tag == 'Code':
                self.code = ns.split(node[0].text, nsmap=faultxml.nsmap)
            elif tag == 'faultstring':
                self.message = node.text
            elif tag == 'Reason':
                self.message = node[0].text
            elif tag == 'detail' or tag == 'Detail':
                faultobj = node[0]
                type = faultobj.get(ET.QName(ns.XSI, 'type'))
                if not type:
                    type = faultobj.tag
                try:
                    faultobj = client.factory(type, faultobj)
                except:
                    pass
                self.detail = faultobj

    def __str__(self):
        return repr(self)

class WSDL(object):
    '''
    WSDL parses and holds a WSDL file.
    '''
    def __init__(self, url=None, nsmap=None, schemaloader=None, **kwargs):
        self.url = url
        self.nsmap = nsmap
        self.documents = []
        if schemaloader is None:
            schemaloader = SchemaLoader
        self.schemaloader = schemaloader

        targetns = self._load(url)
        self.builder = Builder(schemaloader, targetns)
        self.messages = self._messages()

    def _load(self, url):
        doc = ET.parse(urllib2.urlopen(url))
        extrans = doc.getroot().nsmap
        targetns = doc.getroot().get('targetNamespace')
        schemas = doc.findall(ns.expand('*/xs:schema'))
        for s in schemas:
            for k,v in extrans.items():
                if k not in s.nsmap:
                    s.nsmap[k] = v
            self.schemaloader.load(s, pathinfo=self.url)
        self.documents.append(doc)

        wsdls = doc.findall(ns.expand('/wsdl:import'))
        for w in wsdls:
            location = w.get('location')
            location = urljoin(url, location)
            tns = self._load(location)
            if tns:
                targetns = tns

        return targetns

    def find(self, path):
        ret = None
        for doc in self.documents:
            ret = doc.find(path, namespaces=self.nsmap)
            if ret is not None:
                break
        return ret

    def findall(self, path):
        ret = []
        for doc in self.documents:
            ret.extend(doc.findall(path, namespaces=self.nsmap))
        return ret

    def _messages(self):
        messages = {}
        for doc in self.documents:
            r = doc.getroot()
            tns = r.get('targetNamespace')
            for m in doc.findall('wsdl:message', namespaces=self.nsmap):
                messages[ns.expand(m.get('name'), r.nsmap, targetNamespace=tns)] = ns.expand(m[0].get('element'), r.nsmap, targetNamespace=tns)
        return messages
                    

class Operation(object):
    '''
    The Operation class represents a wsdl:operation.
    '''
    def __init__(self, client, btype, op, tns=None):
        self.name = op.get('name')
        portop = client.wsdl.find('wsdl:portType[@name="%s"]/wsdl:operation[@name="%s"]' % (btype, self.name))
        self.imsg = None
        self.ihdr = None
        self.omsg = None
        self.client = client
        self.faults = []
        self.action = '""'
        soapop = op.find(ns.expand('soap:operation', client.nsmap))
        if soapop is not None:
            self.action = '"%s"' % soapop.get('soapAction', '')

        hdr = op.find(ns.expand('soap:header', client.nsmap))
        if hdr is not None:
            msg = client.wsdl.messages[ns.expand(hdr.get('message'), el.nsmap)]
            self.ihdr = msg

        for el in portop:
            (namespace, tag) = ns.split(el.tag)
            if tag not in ('input', 'output', 'fault'):
                continue
            msg = client.wsdl.messages[ns.expand(el.get('message'), el.nsmap)]

            if tag == 'input':
                self.imsg = msg
            if tag == 'output':
                self.omsg = msg
            if tag == 'fault':
                self.faults.append(msg)

    def __call__(self, *args, **kwargs):
        return self.client.invoke(self, *args, **kwargs)

    def __str__(self):
        param = []
        icls = self.client._factory(self.imsg)
        for x in icls.__template__:
            p = '%s %s' % (x[1], x[0])
            if x[3][1] > 1:
                p += '[]'
            param.append(p)

        return '%s(%s)' % (self.name, ', '.join(param))

class Service(object):
    def __init__(self, name):
        self.name = name

    def __str__(self):
        a = []
        a.append('Service %s:' % self.name)
        for v in self.__dict__.values():
            if isinstance(v, Operation):
                a.append('    %s' % str(v))
        return '\n'.join(a)

# This is for testing/playing back traffic.
# If you need to do this, you'll probably need to customize this
# class a bit anyway.
class Injector(object):
    def __init__(self, filename):
        self.filename = filename
        self.file = file(filename, 'r')
        self.number = 0
        self.linenum = 0
        self.lookahead = []

    def _next(self):
        ret = []
        save = 0
        self.number += 1
        for line in self.file:
            self.linenum += 1
            if line.startswith('<SOAP-ENV:Envelope'):
                save = self.linenum
            if save:
                ret.append(line)
            if line.startswith('</SOAP-ENV:Envelope'):
                break

        ret = ''.join(ret)
        log.info('INJECT record %d (line %d), %d bytes returned', self.number, save, len(ret))
        return ret

    def peek(self):
        ret = self._next()
        self.lookahead.append(ret)
        return ret

    def next(self):
        if self.lookahead:
            return self.lookahead.pop(0)
        return self._next()

class Client(object):
    '''
    Client is a SOAP client.
    '''
    __transport__ = urllib2
    def __init__(self, wsdl, url=None, nsmap={}, **kwargs):
        self.nsmap = copy(ns._defns)
        self.nsmap.update(nsmap)
        if isinstance(wsdl, WSDL):
            self.wsdl = wsdl
        else:
            self.wsdl = WSDL(wsdl, nsmap=self.nsmap)

        self.url = url
        self.headers = []
        self.timeout = kwargs.get('timeout', socket._GLOBAL_DEFAULT_TIMEOUT)
        self.retxml = kwargs.get('retxml', False)
        self.httphdr = kwargs.get('httphdr', {})
        self.transport = kwargs.get('transport', self.__transport__)

        self._reqno = 0
        self._inject = None

        self._update_nsmap()
        self._mk_service()

    def _update_nsmap(self):
        '''
        Update our namespace map with the namespaces provided by the WSDL.
        '''
        # These namespaces prefixes are the commonly used prefixes
        # I picked the ones I needed to make SOAP work.
        ns = ('wsdl', 'soap', 'mime', 'wsse', 'wsu', 'soapenv', 'soapenc',
                'soap-env', 'soap-enc')
        for doc in self.wsdl.documents:
            root = doc.getroot()
            nsmap = root.nsmap
            tns = root.get('targetNamespace')
            if tns:
                self.nsmap['tns'] = tns
            for sk in ns:
                # sk = source key, SK = uppercase source key
                # dk = destination key
                SK = sk.upper()
                dk = sk.replace('-', '')
                if sk in nsmap:
                    self.nsmap[dk] = nsmap[sk]
                if SK in nsmap:
                    self.nsmap[dk] = nsmap[SK]

    def _mk_service(self):
        '''
        Build a Service object for each wsdl:service
        '''
        for s in self.wsdl.findall('wsdl:service'):
            name = s.get('name')
            service = Service(name)
            setattr(self, name, service)
            port = s.find(ns.expand('wsdl:port', self.nsmap))
            (_, binding) = ns.split(port.get('binding'), port.nsmap)
            self._mk_binding(binding, service)

    def _mk_binding(self, bname, service):
        '''
        Build operation objects bound to the service
        '''
        #bname = ns.expand(bname, self.nsmap)
        #print "making binding for",bname
        binding = self.wsdl.find('wsdl:binding[@name="%s"]' % bname)
        (_, btype) = ns.split(binding.get('type'), binding.nsmap)
        for op in binding.findall(ns.expand('wsdl:operation', self.nsmap)):
            operation = Operation(self, btype, op)
            setattr(service, op.get('name'), operation)

    def _factory(self, typename):
        '''Construct a classobject for typename'''
        cls = self.wsdl.builder.factory(typename)
        return cls

    def factory(self, typename, *args, **kwargs):
        '''
        Construct an instance for typename.

        Initialize the instance with args and kwargs.
        '''
        return self._factory(typename)(*args, **kwargs)

    def envelope(self, headers, body, bodytag=None):
        '''
        Build a SOAP envelope given headers and body.
        '''
        env = ET.Element(ns.expand('soapenv:Envelope', self.nsmap), nsmap=self.nsmap)
        envheader = ET.Element(ns.expand('soapenv:Header', self.nsmap))
        envbody = ET.Element(ns.expand('soapenv:Body', self.nsmap))
        env.append(envheader)
        env.append(envbody)

        for header in headers:
            if not ET.iselement(header):
                if hasattr(header, '__xml__'):
                    header = header.__xml__()
                else:
                    raise Exception('Cannott create SOAP:header')
            envheader.append(header)
        if body is not None:
            if not ET.iselement(body):
                if hasattr(body, '__xml__'):
                    body = body.__xml__(tag=bodytag)
                else:
                    raise Exception('Cannot create SOAP:body')
            envbody.append(body)
        return env

    def invoke(self, operation, *args, **kwargs):
        '''
        Invoke a SOAP operation.
        '''
        self._reqno += 1
        retxml = kwargs.pop('__retxml__', self.retxml)
        timeout = kwargs.pop('__timeout__', self.timeout)
        transport_options = kwargs.pop('__transport__', {})
        # Create an instance of the request message and initialize
        # the object from the arguments
        param = self.factory(operation.imsg)
        tmpl = param.__template__
        for k,v in zip((t[0] for t in tmpl), args):
            param[k] = v
        for k,v in kwargs.items():
            param[k] = v

        # Build the soap envelope and set the http headers
        payload = self.envelope(self.headers, param, operation.imsg)
        httphdr = { 'Content-Type': 'text/xml', 'SOAPAction': operation.action }
        httphdr.update(self.httphdr)

        # Construct and issue the request, read the response
        payload = ET.tostring(payload, pretty_print=True)
        log.debug('=== SOAP REQUEST ===\n%s', payload)
        req = urllib2.Request(self.url, payload, httphdr)
        try:
            if self._inject:
                xml = ET.fromstring(self._inject.next())
            else:
                if hasattr(self.transport, 'open'):
                    rsp = self.transport.open(req, timeout=timeout, **transport_options)
                else:
                    rsp = self.transport.urlopen(req, timeout=timeout, **transport_options)
                xml = ET.parse(rsp)
        except urllib2.HTTPError as ex:
            xml = ET.parse(ex)

        log.debug('=== SOAP RESPONSE ===\n%s', xmlstr(xml))
        # Get the soap body
        retval = xml.find(ns.expand('soapenv:Body', self.nsmap))
        if not retxml:
            # Does the body contain any nodes?
            if len(retval):
                # Get the first child and examine it
                retval = retval[0]
                namespace, tag = ns.split(retval.tag)
                # If it's a fault, convert it to an exception
                if tag == 'Fault':
                    raise SoapFault(retval, self)
                # Otherwise, deserialize
                obj = self.factory(operation.omsg, retval)
                # If the deserialized
                # object has only one item, return that item, otherwise the
                # whole object
                #
                # This is so if the return value is a single primitive type
                # (like a string), you don't have to dig into an object just
                # to get at the single primitive return value
                if len(obj) == 1:
                    obj = obj[0]
                retval = obj
            else:
                retval = None

        return retval

    def __str__(self):
        a = []
        a.append('Bubbles client')
        for k, v in self.__dict__.items():
            if isinstance(v, Service):
                a.append(str(v))

        return '\n'.join(a)




# VIM options (place at end of file)
# vim: ts=4 sts=4 sw=4 expandtab:
