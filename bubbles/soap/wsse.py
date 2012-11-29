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
#    Punt on WSSE security objects
#
#####################################################
from bubbles.util import ns
from bubbles.dobject import DynamicObject

class Security(DynamicObject):
    '''
    The WSSE Security object is just a container for holding whatever security
    object the server wants.

    You may need to override the __namespace__.

    Example:

        # Create a client an log in to HP Onboard Administrator
        c = Client('hpoa.wsd', url='https://172.17.3.30/hpoa')
        sessionkey = c.hpoa.userLogIn('username', 'password')

        # Create a WSSE Security header with the sessionkey object.
        # Override the namespace to the version of wsse the OA uses and
        # append the object to the client's list of soap headers
        wsse = Security(HpOaSessionKeyToken=sessionkey)
        wsse.__namespace__ = c.nsmap['wsse']
        c.headers.append(wsse)
    '''
    __namespace__ = ns.WSSE

# VIM options (place at end of file)
# vim: ts=4 sts=4 sw=4 expandtab:
