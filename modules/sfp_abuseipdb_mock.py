# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_abuseipdb_mock
# Purpose:     Mock AbuseIPDB module for repeatable IR demos.
#
# Author:      SpiderFoot OSINT Lab
#
# Created:     2024
# Licence:     MIT
# -------------------------------------------------------------------------------

import json
from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_abuseipdb_mock(SpiderFootPlugin):

    meta = {
        'name': "Mock AbuseIPDB",
        'summary': "Query mock threat intel API for AbuseIPDB-style IP abuse reports.",
        'flags': [],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "http://threatintel-api:5000",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [],
            'description': "Mock AbuseIPDB API for OSINT lab IR demonstrations. Crowdsourced IP reputation."
        }
    }

    opts = {
        'api_url': 'http://threatintel-api:5000',
        'confidence_threshold': 50  # Flag as malicious if confidence >= this
    }

    optdescs = {
        'api_url': "URL of the mock threat intel API service.",
        'confidence_threshold': "Minimum abuse confidence score to flag as malicious (0-100)."
    }

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.__dataSource__ = "Mock AbuseIPDB"

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
        url = f"{api_url}/abuseipdb/ip/{eventData}"

        try:
            res = self.sf.fetchUrl(
                url,
                timeout=15,
                useragent=self.opts.get('_useragent', 'SpiderFoot')
            )

            if res['code'] != "200":
                self.debug(f"Mock AbuseIPDB API returned {res['code']} for {eventData}")
                return

            if not res['content']:
                return

            data = json.loads(res['content'])
            abuse_data = data.get('data', {})

            # Store raw data
            evt = SpiderFootEvent(
                "RAW_RIR_DATA",
                json.dumps(abuse_data, indent=2),
                self.__name__,
                event
            )
            self.notifyListeners(evt)

            confidence = abuse_data.get('abuseConfidenceScore', 0)
            total_reports = abuse_data.get('totalReports', 0)
            distinct_users = abuse_data.get('numDistinctUsers', 0)
            isp = abuse_data.get('isp', 'Unknown')
            usage_type = abuse_data.get('usageType', 'Unknown')

            # Flag as malicious if confidence exceeds threshold
            threshold = self.opts.get('confidence_threshold', 50)
            if confidence >= threshold:
                desc = (f"AbuseIPDB: {eventData} has {confidence}% abuse confidence. "
                       f"Total reports: {total_reports} from {distinct_users} users. "
                       f"ISP: {isp}, Usage: {usage_type}")
                evt = SpiderFootEvent("MALICIOUS_IPADDR", desc, self.__name__, event)
                self.notifyListeners(evt)
                self.info(f"AbuseIPDB: {eventData} flagged with {confidence}% confidence")
            elif total_reports > 0:
                self.info(f"AbuseIPDB: {eventData} has {total_reports} reports but only {confidence}% confidence")

        except json.JSONDecodeError:
            self.error(f"Failed to parse mock AbuseIPDB API response for {eventData}")
        except Exception as e:
            self.error(f"Error querying mock AbuseIPDB API: {str(e)}")

# End of sfp_abuseipdb_mock class
