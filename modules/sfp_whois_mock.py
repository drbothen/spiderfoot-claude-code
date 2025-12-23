# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_whois_mock
# Purpose:     Mock WHOIS module for repeatable IR demos.
#
# Author:      SpiderFoot OSINT Lab
#
# Created:     2024
# Licence:     MIT
# -------------------------------------------------------------------------------

import json
from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_whois_mock(SpiderFootPlugin):

    meta = {
        'name': "Mock WHOIS",
        'summary': "Query mock threat intel API for deterministic WHOIS data.",
        'flags': [],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Public Registries"],
        'dataSource': {
            'website': "http://threatintel-api.lab.local:5000",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [],
            'description': "Mock WHOIS for OSINT lab IR demonstrations."
        }
    }

    opts = {
        'api_url': 'http://threatintel-api:5000'
    }

    optdescs = {
        'api_url': "URL of the mock threat intel API service."
    }

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.__dataSource__ = "Mock WHOIS"

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ["IP_ADDRESS"]

    def producedEvents(self):
        return ["RAW_RIR_DATA", "NETBLOCK_OWNER", "BGP_AS_OWNER"]

    def handleEvent(self, event):
        eventData = event.data

        if self.checkForStop():
            return

        if eventData in self.results:
            return

        self.results[eventData] = True

        api_url = self.opts['api_url']
        url = f"{api_url}/whois/ip/{eventData}"

        try:
            res = self.sf.fetchUrl(
                url,
                timeout=15,
                useragent=self.opts.get('_useragent', 'SpiderFoot')
            )

            if res['code'] != "200":
                self.debug(f"Mock WHOIS API returned {res['code']} for {eventData}")
                return

            if not res['content']:
                return

            data = json.loads(res['content'])
            whois_data = data.get('data', {})

            if whois_data.get('message'):
                # No data available
                return

            # Raw WHOIS data
            evt = SpiderFootEvent(
                "RAW_RIR_DATA",
                json.dumps(whois_data, indent=2),
                self.__name__,
                event
            )
            self.notifyListeners(evt)

            # Netblock owner
            org = whois_data.get('org')
            cidr = whois_data.get('cidr')
            if org and cidr:
                evt = SpiderFootEvent(
                    "NETBLOCK_OWNER",
                    f"{cidr} ({org})",
                    self.__name__,
                    event
                )
                self.notifyListeners(evt)

            # ASN owner
            asn = whois_data.get('asn')
            asn_name = whois_data.get('asn_name', 'Unknown')
            if asn:
                evt = SpiderFootEvent(
                    "BGP_AS_OWNER",
                    f"{asn} - {asn_name}",
                    self.__name__,
                    event
                )
                self.notifyListeners(evt)

            self.info(f"Mock WHOIS: {eventData} -> {org}")

        except json.JSONDecodeError:
            self.error(f"Failed to parse mock WHOIS API response for {eventData}")
        except Exception as e:
            self.error(f"Error querying mock WHOIS API: {str(e)}")

# End of sfp_whois_mock class
