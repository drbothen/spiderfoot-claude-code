# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_sslcert_mock
# Purpose:     Mock SSL certificate module for repeatable IR demos.
#
# Author:      SpiderFoot OSINT Lab
#
# Created:     2024
# Licence:     MIT
# -------------------------------------------------------------------------------

import json
from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_sslcert_mock(SpiderFootPlugin):

    meta = {
        'name': "Mock SSL Certificate",
        'summary': "Query mock threat intel API for deterministic SSL cert data.",
        'flags': [],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Crawling and Scanning"],
        'dataSource': {
            'website': "http://threatintel-api.lab.local:5000",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [],
            'description': "Mock SSL cert analyzer for OSINT lab IR demonstrations."
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
        self.__dataSource__ = "Mock SSL"

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ["IP_ADDRESS"]

    def producedEvents(self):
        return ["TCP_PORT_OPEN", "SSL_CERTIFICATE_ISSUED", "SSL_CERTIFICATE_ISSUER"]

    def handleEvent(self, event):
        eventData = event.data

        if self.checkForStop():
            return

        if eventData in self.results:
            return

        self.results[eventData] = True

        api_url = self.opts['api_url']
        url = f"{api_url}/ssl/ip/{eventData}"

        try:
            res = self.sf.fetchUrl(
                url,
                timeout=15,
                useragent=self.opts.get('_useragent', 'SpiderFoot')
            )

            if res['code'] != "200":
                self.debug(f"Mock SSL API returned {res['code']} for {eventData}")
                return

            if not res['content']:
                return

            data = json.loads(res['content'])
            ssl_data = data.get('data', {})

            if ssl_data.get('message'):
                # No data available
                return

            port = ssl_data.get('port', 443)

            # Port open
            evt = SpiderFootEvent(
                "TCP_PORT_OPEN",
                f"{eventData}:{port}",
                self.__name__,
                event
            )
            self.notifyListeners(evt)

            # Certificate subject (issued to)
            subject = ssl_data.get('subject')
            if subject:
                evt = SpiderFootEvent(
                    "SSL_CERTIFICATE_ISSUED",
                    subject,
                    self.__name__,
                    event
                )
                self.notifyListeners(evt)

            # Certificate issuer
            issuer = ssl_data.get('issuer')
            if issuer:
                evt = SpiderFootEvent(
                    "SSL_CERTIFICATE_ISSUER",
                    issuer,
                    self.__name__,
                    event
                )
                self.notifyListeners(evt)

            self.info(f"Mock SSL: {eventData}:{port} -> {subject}")

        except json.JSONDecodeError:
            self.error(f"Failed to parse mock SSL API response for {eventData}")
        except Exception as e:
            self.error(f"Error querying mock SSL API: {str(e)}")

# End of sfp_sslcert_mock class
