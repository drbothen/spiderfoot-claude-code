# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_email_lab
# Purpose:      Lab-patched version of sfp_email that accepts .lab TLD
#               for local testing environments.
#
# Based on:     sfp_email by Steve Micallef <steve@binarypool.com>
# Modified:     2024 for lab testing purposes
# Licence:     MIT
# -------------------------------------------------------------------------------

from spiderfoot import SpiderFootEvent, SpiderFootHelpers, SpiderFootPlugin


class sfp_email_lab(SpiderFootPlugin):

    meta = {
        'name': "E-Mail Address Extractor (Lab)",
        'summary': "Identify e-mail addresses in any obtained data. Patched to accept .lab TLD.",
        'useCases': ["Passive", "Investigate", "Footprint"],
        'categories': ["Content Analysis"]
    }

    opts = {
        'lab_tlds': 'lab,local,test,internal',  # Comma-separated list of local TLDs to accept
    }

    optdescs = {
        'lab_tlds': 'Additional TLDs to accept as valid (comma-separated). For lab/testing environments.',
    }

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ["TARGET_WEB_CONTENT", "BASE64_DATA", "AFFILIATE_DOMAIN_WHOIS",
                "CO_HOSTED_SITE_DOMAIN_WHOIS", "DOMAIN_WHOIS", "NETBLOCK_WHOIS",
                "LEAKSITE_CONTENT", "RAW_DNS_RECORDS", "RAW_FILE_META_DATA",
                'RAW_RIR_DATA', "SIMILARDOMAIN_WHOIS",
                "SSL_CERTIFICATE_RAW", "SSL_CERTIFICATE_ISSUED", "TCP_PORT_OPEN_BANNER",
                "WEBSERVER_BANNER", "WEBSERVER_HTTPHEADERS"]

    def producedEvents(self):
        return ["EMAILADDR", "EMAILADDR_GENERIC", "AFFILIATE_EMAILADDR"]

    def isValidLabTld(self, domain):
        """Check if domain ends with one of the configured lab TLDs."""
        lab_tlds = [t.strip().lower() for t in self.opts['lab_tlds'].split(',')]
        domain_lower = domain.lower()
        for tld in lab_tlds:
            if domain_lower.endswith('.' + tld) or domain_lower == tld:
                return True
        return False

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        emails = SpiderFootHelpers.extractEmailsFromText(eventData)
        for email in set(emails):
            evttype = "EMAILADDR"
            email = email.lower()

            # Get the domain and strip potential ending .
            mailDom = email.split('@')[1].strip('.')

            # Check if it's a lab TLD first (bypass normal validation)
            is_lab_domain = self.isValidLabTld(mailDom)

            if not is_lab_domain:
                # For non-lab domains, use standard validation
                if not self.sf.validHost(mailDom, self.opts.get('_internettlds', '')):
                    self.debug(f"Skipping {email} as not a valid e-mail.")
                    continue
            else:
                self.info(f"Accepting lab domain email: {email}")

            if not self.getTarget().matches(mailDom, includeChildren=True, includeParents=True) and not self.getTarget().matches(email):
                self.debug("External domain, so possible affiliate e-mail")
                evttype = "AFFILIATE_EMAILADDR"

            if eventName.startswith("AFFILIATE_"):
                evttype = "AFFILIATE_EMAILADDR"

            if not evttype.startswith("AFFILIATE_") and email.split("@")[0] in self.opts.get('_genericusers', '').split(","):
                evttype = "EMAILADDR_GENERIC"

            self.info(f"Found e-mail address: {email}")
            mail = email.strip('.')

            evt = SpiderFootEvent(evttype, mail, self.__name__, event)
            if event.moduleDataSource:
                evt.moduleDataSource = event.moduleDataSource
            else:
                evt.moduleDataSource = "Unknown"
            self.notifyListeners(evt)

# End of sfp_email_lab class
