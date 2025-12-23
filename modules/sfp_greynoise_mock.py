# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_greynoise_mock
# Purpose:     Mock GreyNoise module for repeatable IR demos.
#
# Author:      SpiderFoot OSINT Lab
#
# Created:     2024
# Licence:     MIT
# -------------------------------------------------------------------------------

import json
from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_greynoise_mock(SpiderFootPlugin):

    meta = {
        'name': "Mock GreyNoise",
        'summary': "Query mock threat intel API for GreyNoise-style noise classification.",
        'flags': [],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "http://threatintel-api:5000",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [],
            'description': "Mock GreyNoise API for OSINT lab IR demonstrations. Distinguishes internet background noise from targeted attacks."
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
        self.__dataSource__ = "Mock GreyNoise"

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ["IP_ADDRESS"]

    def producedEvents(self):
        return ["MALICIOUS_IPADDR", "RAW_RIR_DATA"]

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
        url = f"{api_url}/greynoise/ip/{eventData}"

        try:
            res = self.sf.fetchUrl(
                url,
                timeout=15,
                useragent=self.opts.get('_useragent', 'SpiderFoot')
            )

            if res['code'] != "200":
                self.debug(f"Mock GreyNoise API returned {res['code']} for {eventData}")
                return

            if not res['content']:
                return

            data = json.loads(res['content'])
            gn_data = data.get('data', {})

            # Store raw data
            evt = SpiderFootEvent(
                "RAW_RIR_DATA",
                json.dumps(gn_data, indent=2),
                self.__name__,
                event
            )
            self.notifyListeners(evt)

            classification = gn_data.get('classification', 'unknown')
            noise = gn_data.get('noise', False)
            riot = gn_data.get('riot', False)
            name = gn_data.get('name', 'Unknown')
            message = gn_data.get('message', '')

            # Only flag as malicious if GreyNoise says malicious AND not noise
            if classification == "malicious" and not noise:
                desc = (f"GreyNoise: {eventData} classified as MALICIOUS (targeted attack). "
                       f"Name: {name}. {message}")
                evt = SpiderFootEvent("MALICIOUS_IPADDR", desc, self.__name__, event)
                self.notifyListeners(evt)
                self.info(f"GreyNoise: {eventData} is malicious (targeted)")
            elif classification == "benign":
                # Log benign classification (important for divergent intel demos)
                self.info(f"GreyNoise: {eventData} is BENIGN. {message}")
            elif noise:
                self.info(f"GreyNoise: {eventData} is internet background noise. {message}")

        except json.JSONDecodeError:
            self.error(f"Failed to parse mock GreyNoise API response for {eventData}")
        except Exception as e:
            self.error(f"Error querying mock GreyNoise API: {str(e)}")

# End of sfp_greynoise_mock class
