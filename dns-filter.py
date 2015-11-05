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

  Additionally, this program can also strip unwanted A records from the
  responses returned by upstream.

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

import os
import sys
import yaml

from twisted.names import client, server, dns, error
from twisted.python import failure
from twisted.application import service, internet

config_file = os.environ.get('DNS_FILTER_CONF', '/etc/dns-filter.yml')

try:
    with open(config_file, 'r') as f:
        config = yaml.load(f)
except IOError:
    print "Config file not found: {config_file}".format(config_file=config_file)
    sys.exit(2)
except yaml.parser.ParserError:
    print "Failed to parse config file."
    sys.exit(2)


class MyResolver(client.Resolver):
    def filterAnswers(self, x):
        if x.trunc:
            return self.queryTCP(x.queries).addCallback(self.filterAnswers)

        if x.rCode != dns.OK:
            f = self._errormap.get(x.rCode, error.DNSUnknownError)(x)
            return failure.Failure(f)

        # We're only interested in 'A' records
        for y in x.answers:
            if not isinstance(y.payload, dns.Record_A):
                continue

            # Strip unwanted IPs
            if y.payload.dottedQuad() in self.stripped:
                x.answers.remove(y)
                continue

            # Report failure if we encounter one of the invalid
            if y.payload.dottedQuad() in self.invalid:
                f = self._errormap.get(x.rCode, error.DomainError)(x)
                return failure.Failure(f)

        return (x.answers, x.authority, x.additional)

# Configure our custom resolver
resolver = MyResolver(servers=[(
    config['server']['upstream']['host'],
    config['server']['upstream']['port'],
)])
resolver.invalid = config['rules']['invalid']
resolver.stripped = config['rules']['stripped']

factory = server.DNSServerFactory(clients=[resolver])
protocol = dns.DNSDatagramProtocol(factory)

dnsFilterService = internet.UDPServer(
    config['server']['listen']['port'],
    protocol,
    config['server']['listen']['host'],
)
application = service.Application("DNS filter")
dnsFilterService.setServiceParent(application)
