# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_shodan_mock
# Purpose:     Mock Shodan module for repeatable IR demos.
#
# Author:      SpiderFoot OSINT Lab
#
# Created:     2024
# Licence:     MIT
# -------------------------------------------------------------------------------

import json
from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_shodan_mock(SpiderFootPlugin):

    meta = {
        'name': "Mock Shodan",
        'summary': "Query mock threat intel API for Shodan-style service discovery.",
        'flags': [],
        'useCases': ["Investigate", "Passive", "Footprint"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "http://threatintel-api.lab.local:5000",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [],
            'description': "Mock Shodan API for OSINT lab IR demonstrations. Infrastructure fingerprinting."
        }
    }

    opts = {
        'api_url': 'http://threatintel-api.lab.local:5000'
    }

    optdescs = {
        'api_url': "URL of the mock threat intel API service."
    }

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.__dataSource__ = "Mock Shodan"

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ["IP_ADDRESS"]

    def producedEvents(self):
        return ["TCP_PORT_OPEN", "OPERATING_SYSTEM", "WEBSERVER_BANNER",
                "SOFTWARE_USED", "VULNERABILITY_CVE_CRITICAL", "RAW_RIR_DATA"]

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        if self.checkForStop():
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        api_url = self.opts['api_url']
        url = f"{api_url}/shodan/ip/{eventData}"

        try:
            res = self.sf.fetchUrl(
                url,
                timeout=15,
                useragent=self.opts.get('_useragent', 'SpiderFoot')
            )

            if res['code'] != "200":
                self.debug(f"Mock Shodan API returned {res['code']} for {eventData}")
                return

            if not res['content']:
                return

            data = json.loads(res['content'])
            shodan_data = data.get('data', {})

            # Store raw data
            evt = SpiderFootEvent(
                "RAW_RIR_DATA",
                json.dumps(shodan_data, indent=2),
                self.__name__,
                event
            )
            self.notifyListeners(evt)

            # Report open ports
            ports = shodan_data.get('ports', [])
            for port in ports:
                evt = SpiderFootEvent(
                    "TCP_PORT_OPEN",
                    f"{eventData}:{port}",
                    self.__name__,
                    event
                )
                self.notifyListeners(evt)

            # Report service banners
            services = shodan_data.get('data', [])
            for svc in services:
                product = svc.get('product', 'Unknown')
                version = svc.get('version', '')
                port = svc.get('port', 'Unknown')

                software_info = f"{product} {version}".strip()
                evt = SpiderFootEvent(
                    "SOFTWARE_USED",
                    f"{software_info} on port {port}",
                    self.__name__,
                    event
                )
                self.notifyListeners(evt)

            # Report vulnerabilities
            vulns = shodan_data.get('vulns', [])
            for vuln in vulns:
                evt = SpiderFootEvent(
                    "VULNERABILITY_CVE_CRITICAL",
                    f"{eventData}: {vuln}",
                    self.__name__,
                    event
                )
                self.notifyListeners(evt)
                self.info(f"Shodan: {eventData} vulnerable to {vuln}")

            # Report hostnames
            hostnames = shodan_data.get('hostnames', [])
            for hostname in hostnames:
                self.info(f"Shodan: {eventData} resolves to {hostname}")

            # Report tags (like tor, proxy, c2)
            tags = shodan_data.get('tags', [])
            if tags:
                self.info(f"Shodan: {eventData} tagged as: {', '.join(tags)}")

        except json.JSONDecodeError:
            self.error(f"Failed to parse mock Shodan API response for {eventData}")
        except Exception as e:
            self.error(f"Error querying mock Shodan API: {str(e)}")

# End of sfp_shodan_mock class
