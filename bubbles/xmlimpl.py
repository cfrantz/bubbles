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
#    Import ElementTree.  Pick lxml as the preferred version
#
#####################################################

#try:
#    import lxml.etree as ET
#except ImportError:
#    import xml.etree.ElementTree as ET
import lxml.etree as ET

class xmlstr:
    '''
    A class that defers ET.tostring until the instance is
    evaluated in string context.

    Use this to print xml etrees in debug statements:

        xml = ET.parse(...)
        log.debug("The xml was: %s", xmlstr(xml))
    '''
    def __init__(self, xml):
        self.xml = xml
    def __str__(self):
        return ET.tostring(self.xml, pretty_print=True)

__all__ = [ 'ET', 'xmlstr']

# VIM options (place at end of file)
# vim: ts=4 sts=4 sw=4 expandtab:
