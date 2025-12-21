# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_breach_api
# Purpose:     Check email addresses against the local breach database API.
#
# Author:      SpiderFoot OSINT Lab
#
# Created:     2024
# Licence:     MIT
# -------------------------------------------------------------------------------

import json
from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_breach_api(SpiderFootPlugin):

    meta = {
        'name': "Local Breach API",
        'summary': "Check email addresses against the lab's breach database API.",
        'flags': [],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Leaks, Dumps and Breaches"],
        'dataSource': {
            'website': "http://breach-api.lab.local:5000",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [],
            'description': "Local breach database for OSINT lab demonstrations."
        }
    }

    opts = {
        'api_url': 'http://breach-api.lab.local:5000',
        'check_affiliates': True
    }

    optdescs = {
        'api_url': "URL of the breach API service.",
        'check_affiliates': "Check affiliates' email addresses?"
    }

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.__dataSource__ = "Local Breach API"

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ["EMAILADDR", "EMAILADDR_GENERIC", "AFFILIATE_EMAILADDR"]

    def producedEvents(self):
        return ["EMAILADDR_COMPROMISED"]

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        # Honor scan cancellation
        if self.checkForStop():
            return

        # Skip if already processed
        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        # Skip affiliate emails if configured
        if eventName == "AFFILIATE_EMAILADDR" and not self.opts['check_affiliates']:
            return

        self.results[eventData] = True
        self.debug(f"Checking {eventData} against breach API")

        # Query the breach API
        api_url = self.opts['api_url']
        url = f"{api_url}/breaches?email={eventData}"

        try:
            res = self.sf.fetchUrl(
                url,
                timeout=15,
                useragent=self.opts.get('_useragent', 'SpiderFoot')
            )

            if res['code'] != "200":
                self.debug(f"Breach API returned {res['code']} for {eventData}")
                return

            if not res['content']:
                return

            data = json.loads(res['content'])

            if data.get('found', False) and data.get('breaches'):
                for breach in data['breaches']:
                    breach_name = breach.get('name', 'Unknown Breach')
                    breach_date = breach.get('date', 'Unknown Date')
                    breach_records = breach.get('records', 0)
                    data_types = ', '.join(breach.get('data_types', []))

                    breach_info = (
                        f"{eventData} found in breach: {breach_name} "
                        f"(Date: {breach_date}, Records: {breach_records}, "
                        f"Exposed: {data_types})"
                    )

                    evt = SpiderFootEvent(
                        "EMAILADDR_COMPROMISED",
                        breach_info,
                        self.__name__,
                        event
                    )
                    self.notifyListeners(evt)

                self.info(f"Found {len(data['breaches'])} breaches for {eventData}")

        except json.JSONDecodeError:
            self.error(f"Failed to parse breach API response for {eventData}")
        except Exception as e:
            self.error(f"Error querying breach API: {str(e)}")

# End of sfp_breach_api class
