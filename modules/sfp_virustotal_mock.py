# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_virustotal_mock
# Purpose:     Mock VirusTotal module for repeatable IR demos.
#
# Author:      SpiderFoot OSINT Lab
#
# Created:     2024
# Licence:     MIT
# -------------------------------------------------------------------------------

import json
from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_virustotal_mock(SpiderFootPlugin):

    meta = {
        'name': "Mock VirusTotal",
        'summary': "Query mock threat intel API for VirusTotal-style IP/domain reputation.",
        'flags': [],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "http://threatintel-api:5000",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [],
            'description': "Mock VirusTotal API for OSINT lab IR demonstrations."
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
        self.__dataSource__ = "Mock VirusTotal"

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ["IP_ADDRESS", "INTERNET_NAME", "DOMAIN_NAME"]

    def producedEvents(self):
        return ["MALICIOUS_IPADDR", "MALICIOUS_INTERNET_NAME", "RAW_RIR_DATA"]

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

        try:
            if eventName == "IP_ADDRESS":
                url = f"{api_url}/virustotal/ip/{eventData}"
            else:
                url = f"{api_url}/virustotal/domain/{eventData}"

            res = self.sf.fetchUrl(
                url,
                timeout=15,
                useragent=self.opts.get('_useragent', 'SpiderFoot')
            )

            if res['code'] != "200":
                self.debug(f"Mock VirusTotal API returned {res['code']} for {eventData}")
                return

            if not res['content']:
                return

            data = json.loads(res['content'])
            vt_data = data.get('data', {})

            # Store raw data
            evt = SpiderFootEvent(
                "RAW_RIR_DATA",
                json.dumps(vt_data, indent=2),
                self.__name__,
                event
            )
            self.notifyListeners(evt)

            # Check for malicious indicators
            malicious = vt_data.get('malicious', 0)
            suspicious = vt_data.get('suspicious', 0)
            total_flags = malicious + suspicious

            if total_flags > 5:
                if eventName == "IP_ADDRESS":
                    evt_type = "MALICIOUS_IPADDR"
                    desc = (f"VirusTotal: {eventData} flagged by {malicious} vendors as malicious, "
                           f"{suspicious} as suspicious. Tags: {', '.join(vt_data.get('tags', []))}")
                else:
                    evt_type = "MALICIOUS_INTERNET_NAME"
                    desc = (f"VirusTotal: {eventData} flagged by {malicious} vendors as malicious, "
                           f"{suspicious} as suspicious.")

                evt = SpiderFootEvent(evt_type, desc, self.__name__, event)
                self.notifyListeners(evt)

                self.info(f"VirusTotal: {eventData} flagged by {total_flags} vendors")

        except json.JSONDecodeError:
            self.error(f"Failed to parse mock VirusTotal API response for {eventData}")
        except Exception as e:
            self.error(f"Error querying mock VirusTotal API: {str(e)}")

# End of sfp_virustotal_mock class
