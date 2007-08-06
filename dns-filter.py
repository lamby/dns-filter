#!/usr/bin/env python

"""
  dns-filter.py

  A simple DNS proxy that returns NXDOMAIN if the master offers an IP from a
  specified blacklist.

  This is useful for broken ISPs that have an obnoxious and RFC-violating "The
  page you were looking for cannot be found" website for all unregistered
  domains, and you don't want to install Bind[0] or djbdns[1].

  See also [2] [3] [4].

     [0] http://www.isc.org/sw/bind/
     [1] http://cr.yp.to/djbdns.htmle
     [2] http://www.nanog.org/mtg-0310/pdf/woolf.pdf (PDF slides)
     [3] http://en.wikipedia.org/wiki/Wildcard_DNS_record
     [4] http://en.wikipedia.org/wiki/Site_Finder


   Copyright (C) 2007  Chris Lamb <chris@chris-lamb.co.uk>

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

# DNS server to get results from
master = '192.168.0.1'

# Invalid 'A' record IP addresses. The program will return "no such
# domain" if one of these addresses is offered.
invalid = ('195.238.237.142', '195.238.237.143')

from twisted.application import service, internet
from twisted.internet.protocol import Factory, Protocol
from twisted.internet import reactor
from twisted.names import client, server, dns, error
from twisted.python import failure
import sys

class MyResolver(client.Resolver):
    def filterAnswers(self, message):
        if message.trunc:
            return self.queryTCP(message.queries).addCallback(self.filterAnswers)
        if message.rCode != dns.OK:
            return failure.Failure(self._errormap.get(message.rCode, error.DNSUnknownError)(message))

        # We're only interested in 'A' records
        for a in filter(lambda x: isinstance(x.payload, dns.Record_A), message.answers):
            # Report failure if we encounter one of the invalid
            if a.payload.dottedQuad() in self.invalid:
                return failure.Failure(self._errormap.get(message.rCode, error.DomainError)(message))

        return (message.answers, message.authority, message.additional)

# Configure our custom resolver
resolver = MyResolver(servers=[(master, 53)])
resolver.invalid = invalid

factory = server.DNSServerFactory(clients=[resolver])
protocol = dns.DNSDatagramProtocol(factory)

dnsFilterService = internet.UDPServer(53, protocol)
application = service.Application("DNS filter")
dnsFilterService.setServiceParent(application)
