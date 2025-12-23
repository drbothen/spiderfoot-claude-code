# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_dnsresolve_mock
# Purpose:     Mock DNS resolver for repeatable IR demos.
#
# Author:      SpiderFoot OSINT Lab
#
# Created:     2024
# Licence:     MIT
# -------------------------------------------------------------------------------

import json
from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_dnsresolve_mock(SpiderFootPlugin):

    meta = {
        'name': "Mock DNS Resolver",
        'summary': "Query mock threat intel API for deterministic DNS resolution.",
        'flags': [],
        'useCases': ["Investigate", "Passive"],
        'categories': ["DNS"],
        'dataSource': {
            'website': "http://threatintel-api.lab.local:5000",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [],
            'description': "Mock DNS resolver for OSINT lab IR demonstrations."
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
        self.__dataSource__ = "Mock DNS"

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ["IP_ADDRESS"]

    def producedEvents(self):
        return ["INTERNET_NAME", "INTERNET_NAME_UNRESOLVED"]

    def handleEvent(self, event):
        eventData = event.data

        if self.checkForStop():
            return

        if eventData in self.results:
            return

        self.results[eventData] = True

        api_url = self.opts['api_url']
        url = f"{api_url}/dns/reverse/{eventData}"

        try:
            res = self.sf.fetchUrl(
                url,
                timeout=15,
                useragent=self.opts.get('_useragent', 'SpiderFoot')
            )

            if res['code'] != "200":
                self.debug(f"Mock DNS API returned {res['code']} for {eventData}")
                return

            if not res['content']:
                return

            data = json.loads(res['content'])
            dns_data = data.get('data', {})

            hostname = dns_data.get('reverse')
            if hostname:
                forward_match = dns_data.get('forward_match', False)
                event_type = "INTERNET_NAME" if forward_match else "INTERNET_NAME_UNRESOLVED"

                evt = SpiderFootEvent(
                    event_type,
                    hostname,
                    self.__name__,
                    event
                )
                self.notifyListeners(evt)
                self.info(f"Mock DNS: {eventData} -> {hostname}")

        except json.JSONDecodeError:
            self.error(f"Failed to parse mock DNS API response for {eventData}")
        except Exception as e:
            self.error(f"Error querying mock DNS API: {str(e)}")

# End of sfp_dnsresolve_mock class
