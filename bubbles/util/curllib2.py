#####################################################
#
# curllib2.py
#
# Copyright 2011 Hewlett-Packard Development Company, L.P.
#
# Hewlett-Packard and the Hewlett-Packard logo are trademarks of
# Hewlett-Packard Development Company, L.P. in the U.S. and/or other countries.
#
# Confidential computer software. Valid license from Hewlett-Packard required
# for possession, use or copying. Consistent with FAR 12.211 and 12.212,
# Commercial Computer Software, Computer Software Documentation, and Technical
# Data for Commercial Items are licensed to the U.S. Government under
# vendor's standard commercial license.
#
# Author:
#    Chris Frantz
# 
# Description:
#    An almost-drop-in replacement for urlilb2 that uses pyCurl to
#    handle urls.
#
#    1. Has a ConnectionCache for storing Curl objects.  Curl objects
#       are kept and re-used.  This means fewer new connections, which is
#       especially helpful for SSL.
#
#    2. Supports curl's various auth schemes by way of urllib2's PasswordMgr.
#       Should be able to add_handler(HTTPBasicAuthHandler) to add credentials.
#
#    3. Supports urllib2's Request object as well as URLError and HTTPError.
#
# TODO:
#    Cookiejar support.
#
#####################################################

import pycurl
from urllib import addinfourl
from urllib2 import Request, URLError, HTTPError, HTTPPasswordMgr
from httplib import BadStatusLine, HTTPMessage
import socket
import time
import re
import threading
from logging import getLogger

log = getLogger(__name__)

try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO

class Curl:
    # XXX this allows for multiple auth-schemes, but will stupidly pick
    # the last one with a realm specified.

    # allow for double- and single-quoted realm values
    # (single quotes are a violation of the RFC, but appear in the wild)
    rx = re.compile('(?:.*,)*[ \t]*([^ \t]+)[ \t]+'
                    'realm=(["\'])(.*?)\\2', re.I)

    def __init__(self):
        self.handle = pycurl.Curl()
        self.handle.setopt(pycurl.WRITEFUNCTION, self._payload_cb)
        self.handle.setopt(pycurl.HEADERFUNCTION, self._header_cb)
        self.handle.setopt(pycurl.SSL_VERIFYHOST, 0)
        self.handle.setopt(pycurl.SSL_VERIFYPEER, 0)
        self.handle.setopt(pycurl.MAXREDIRS, 5)
        self.handle.setopt(pycurl.NOSIGNAL, 1)
        self.handle.setopt(pycurl.COOKIEFILE, '/dev/null')

        self.http_raise = True
        self._time = time.time()

    def set_timeout(self, timeout):
        self.handle.setopt(pycurl.TIMEOUT, timeout)

    def _payload_cb(self, data):
        self.payload.append(data)

    def _header_cb(self, data):
        self.headers.append(data)

    def retry_auth(self, status, headers, req, opener):
        # Check the response headers for known authentication requets
        if status == 401:
            authreq = 'www-authenticate'
        elif status == 407:
            authreq = 'proxy-authenticate'
        else:
            return None

        authreq = headers.get(authreq, '')
        match = self.rx.search(authreq)
        if match:
            # If we get a match from one of the auth headers, look up the realm
            # and set the un/pw in the curl handle.
            scheme, quote, realm = match.groups()
            un, pw = opener.password.find_user_password(realm, req.get_full_url())
            if status == 401:
                self.handle.setopt(pycurl.HTTPAUTH, pycurl.HTTPAUTH_ANY)
                self.handle.setopt(pycurl.USERPWD, '%s:%s' % (un, pw))
            elif status == 407:
                self.handle.setopt(pycurl.PROXYAUTH, pycurl.HTTPAUTH_ANY)
                self.handle.setopt(pycurl.PROXYUSERPWD, '%s:%s' % (un, pw))
            # Retry the request.  Don't pass the opener this time so a second
            # auth failure will result in an HTTPError exception
            return self.request(req)
        return None

    def request(self, req, opener=None):
        # Set _cachekey so CurlOpener knows where to put us in the
        # ConnectionCache
        self._cachekey = (req.get_type(), req.get_host())

        # New payload and headers
        self.payload = []
        self.headers = []

        # Create the list of headers that will be passed into
        # the transaction
        headers = [': '.join(item).encode('utf8') for item in req.header_items()]

        # Set up the request in the curl handle
        # For POST and POST-like requests, delete the Expect header since
        # we don't want to deal with 100-Continue.  Deleting headers is done
        # by setting an empty header.
        method = req.get_method()
        data = req.get_data()
        if data is None:
            data = ''
        data = data.encode('utf8')
        if method == 'GET':
            self.handle.setopt(pycurl.HTTPGET, 1)
        elif method == 'HEAD':
            pass
        elif method == 'POST':
            self.handle.setopt(pycurl.POST, 1)
            self.handle.setopt(pycurl.POSTFIELDS, data)
            headers.append('Expect:')
        else:
            self.handle.setopt(pycurl.POST, 1)
            self.handle.setopt(pycurl.POSTFIELDS, data)
            self.handle.setopt(pycurl.CUSTOMREQUEST, method)
            headers.append('Expect:')

        # Set the headers and URL and perform the request
        self.handle.setopt(pycurl.HTTPHEADER, headers)
        self.handle.setopt(pycurl.URL, str(req.get_full_url()))
        try:
            self.handle.perform()
            self._time = time.time()
        except pycurl.error as e:
            raise URLError(e[1])

        # Put the received headers and payload into file-like objects
        headers = StringIO(''.join(self.headers)) 
        payload = StringIO(''.join(self.payload)) 

        # Get rid of the header and payload arrays (don't want extra references
        # to that data)
        self.headers = self.payload = None

        # Process the response
        # Read the first line (e.g. HTTP/1.1 200 OK)
        line = headers.readline()
        if not line:
            raise BadStatusLine(line)

        # Get the status
        (version, status, reason) = line.split(None, 2)
        try:
            status = int(status)
            if status < 100 or status > 999:
                raise BadStatusLine(line)
        except ValueError:
            raise BadStatusLine(line)

        # Create an HTTPMessage object out of the remaining headers
        httpmsg = HTTPMessage(headers)
        if status in (401, 407) and opener:
            # If there was an auth problem, retry the request with a un/pw
            # from the opener.
            resp = self.retry_auth(status, httpmsg, req, opener)
            if resp:
                return resp

        # Check the HTTP status code.  Any 2xx code is good.  All other codes
        # result in an exception.
        if int(status/100) != 2 and self.http_raise:
            raise HTTPError(req.get_full_url(), status, reason, httpmsg, payload)

        # Create the file-like object holding the payload, the headers and the
        # HTTP status code/reason.
        resp = addinfourl(payload, httpmsg, req.get_full_url())
        resp.code = status
        resp.msg = reason
        return resp

    def close(self):
        if self.handle:
            self.handle.close()
            self.handle=None
        self.headers = None
        self.payload = None

    def __del__(self):
        self.close()

class ConnectionCache:
    def __init__(self, name=None):
        self.name = name or self.__class__.__name__
        self.lock = threading.Lock()
        self.cache = {}
        self.timeout = 300
        self.thread = threading.Thread(name=self.name, target=self.run)
        self.thread.daemon = True
        self.running = True
        self.thread.start()

    def _get(self, req):
        k = (req.get_type(), req.get_host())
        try:
            queue = self.cache[k]
        except KeyError:
            queue = [ ]
            self.cache[k] = queue

        try:
            return queue.pop()
        except IndexError:
            return None

    def get(self, req):
        with self.lock:
            return self._get(req)

    def _put(self, curl):
        k = curl._cachekey
        try:
            queue = self.cache[k]
        except KeyError:
            queue = [ ]
            self.cache[k] = queue
        queue.append(curl)

    def put(self, curl):
        with self.lock:
            return self._put(curl)

    def expire(self, timeout):
        with self.lock:
            now = time.time()
            for key, values in self.cache.items():
                if values:
                    keep = []
                    for curl in values:
                        if now-curl._time < timeout:
                            keep.append(curl)
                        else:
                            curl.close()
                    self.cache[key] = keep

    def run(self):
        while self.running:
            time.sleep(self.timeout)
            self.expire(self.timeout)

_global_ccache = ConnectionCache()

class CurlOpener:
    def __init__(self, cache=_global_ccache):
        self.cache = cache
        self.password = HTTPPasswordMgr()

    def add_password(self, realm, uri, user, passwd):
        self.password.add_password(realm, uri, user, passwd)

    def add_handler(self, handler):
        if instanceof(handler, AbstractBasicAuthHandler):
            for (realm, uris) in handler.passwd.passwd.items():
                for (uri, (un, pw)) in uris.item():
                    self.add_password(realm, uri, un, pw)

    def open(self, fullurl, data=None, timeout=socket._GLOBAL_DEFAULT_TIMEOUT):
        if isinstance(fullurl, basestring):
            req = Request(fullurl, data)
        else:
            req = fullurl
            if data is not None:
                req.add_data(data)

        c = None
        if self.cache:
            c = self.cache.get(req)

        if not c:
            c = Curl()

        if timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:
            c.set_timeout(timeout)

        try:
            resp = c.request(req, self)
        finally:
            self.cache.put(c)
        return resp
        
_opener = None

def urlopen(url, data=None, timeout=socket._GLOBAL_DEFAULT_TIMEOUT):
    global _opener
    if _opener is None:
        _opener = CurlOpener()
    return _opener.open(url, data, timeout)

def install_opener(opener):
    global _opener
    _opener = opener

# VIM options (place at end of file)
# vim: ts=4 sts=4 sw=4 expandtab:
