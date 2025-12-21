#!/usr/bin/env python3
"""
Configure SpiderFoot API Keys and Module Options from Environment Variables

This script reads API keys and module options from environment variables
(or .env file) and seeds them into SpiderFoot's configuration.

Environment variable formats:

1. API Keys (predefined mappings):
    SFP_MODULENAME_OPTIONNAME=value
    Examples:
        SFP_SHODAN_API_KEY=abc123
        SFP_VIRUSTOTAL_API_KEY=xyz789

2. Generic Module Options (any SpiderFoot module setting):
    SFOPT_<MODULE>_<OPTION>=value
    The module name uses underscores (e.g., _stor_db becomes __stor_db)
    Examples:
        SFOPT__STOR_DB_MAXSTORAGE=0      -> sfp__stor_db:maxstorage=0
        SFOPT_SPIDER_MAXPAGES=100        -> sfp_spider:maxpages=100
        SFOPT_BREACH_API_API_URL=http://... -> sfp_breach_api:api_url=...

Usage:
    python configure_api_keys.py [--db-path /path/to/spiderfoot.db]

The script will:
1. Wait for the SpiderFoot database to exist (with timeout)
2. Read API keys and module options from environment variables
3. Update the database/config with the configured settings
"""

import argparse
import json
import os
import re
import sqlite3
import sys
import time
from pathlib import Path

try:
    import requests
except ImportError:
    requests = None


# Map environment variable patterns to SpiderFoot module option names
# Format: (env_var_suffix, module_name, option_name)
ENV_TO_MODULE_MAP = {
    # Abstract API
    "ABSTRACTAPI_COMPANYENRICHMENT_API_KEY": ("sfp_abstractapi", "companyenrichment_api_key"),
    "ABSTRACTAPI_IPGEOLOCATION_API_KEY": ("sfp_abstractapi", "ipgeolocation_api_key"),
    "ABSTRACTAPI_PHONEVALIDATION_API_KEY": ("sfp_abstractapi", "phonevalidation_api_key"),
    # AbuseIPDB
    "ABUSEIPDB_API_KEY": ("sfp_abuseipdb", "api_key"),
    # Abusix
    "ABUSIX_API_KEY": ("sfp_abusix", "api_key"),
    # AlienVault
    "ALIENVAULT_API_KEY": ("sfp_alienvault", "api_key"),
    # BinaryEdge
    "BINARYEDGE_API_KEY": ("sfp_binaryedge", "binaryedge_api_key"),
    # Bing
    "BINGSEARCH_API_KEY": ("sfp_bingsearch", "api_key"),
    "BINGSHAREDIP_API_KEY": ("sfp_bingsharedip", "api_key"),
    # Bitcoin
    "BITCOINABUSE_API_KEY": ("sfp_bitcoinabuse", "api_key"),
    "BITCOINWHOSWHO_API_KEY": ("sfp_bitcoinwhoswho", "api_key"),
    # BotScout
    "BOTSCOUT_API_KEY": ("sfp_botscout", "api_key"),
    # BuiltWith
    "BUILTWITH_API_KEY": ("sfp_builtwith", "api_key"),
    # C99
    "C99_API_KEY": ("sfp_c99", "api_key"),
    # Censys
    "CENSYS_API_KEY_UID": ("sfp_censys", "censys_api_key_uid"),
    "CENSYS_API_KEY_SECRET": ("sfp_censys", "censys_api_key_secret"),
    # CertSpotter
    "CERTSPOTTER_API_KEY": ("sfp_certspotter", "api_key"),
    # CIRCL
    "CIRCLLU_API_KEY_LOGIN": ("sfp_circllu", "api_key_login"),
    "CIRCLLU_API_KEY_PASSWORD": ("sfp_circllu", "api_key_password"),
    # Citadel
    "CITADEL_API_KEY": ("sfp_citadel", "api_key"),
    # Clearbit
    "CLEARBIT_API_KEY": ("sfp_clearbit", "api_key"),
    # Dehashed
    "DEHASHED_API_KEY": ("sfp_dehashed", "api_key"),
    "DEHASHED_API_KEY_USERNAME": ("sfp_dehashed", "api_key_username"),
    # DNSDB
    "DNSDB_API_KEY": ("sfp_dnsdb", "api_key"),
    # EmailCrawlr
    "EMAILCRAWLR_API_KEY": ("sfp_emailcrawlr", "api_key"),
    # EmailRep
    "EMAILREP_API_KEY": ("sfp_emailrep", "api_key"),
    # Etherscan
    "ETHERSCAN_API_KEY": ("sfp_etherscan", "api_key"),
    # Focsec
    "FOCSEC_API_KEY": ("sfp_focsec", "api_key"),
    # FraudGuard
    "FRAUDGUARD_API_KEY_ACCOUNT": ("sfp_fraudguard", "fraudguard_api_key_account"),
    "FRAUDGUARD_API_KEY_PASSWORD": ("sfp_fraudguard", "fraudguard_api_key_password"),
    # FullContact
    "FULLCONTACT_API_KEY": ("sfp_fullcontact", "api_key"),
    # FullHunt
    "FULLHUNT_API_KEY": ("sfp_fullhunt", "api_key"),
    # Google
    "GOOGLEMAPS_API_KEY": ("sfp_googlemaps", "api_key"),
    "GOOGLESAFEBROWSING_API_KEY": ("sfp_googlesafebrowsing", "api_key"),
    "GOOGLESEARCH_API_KEY": ("sfp_googlesearch", "api_key"),
    # GrayHatWarfare
    "GRAYHATWARFARE_API_KEY": ("sfp_grayhatwarfare", "api_key"),
    # GreyNoise
    "GREYNOISE_API_KEY": ("sfp_greynoise", "api_key"),
    "GREYNOISE_COMMUNITY_API_KEY": ("sfp_greynoise_community", "api_key"),
    # Have I Been Pwned
    "HAVEIBEENPWNED_API_KEY": ("sfp_haveibeenpwned", "api_key"),
    # Honeypot
    "HONEYPOT_API_KEY": ("sfp_honeypot", "api_key"),
    # Host.io
    "HOSTIO_API_KEY": ("sfp_hostio", "api_key"),
    # Hunter
    "HUNTER_API_KEY": ("sfp_hunter", "api_key"),
    # Hybrid Analysis
    "HYBRID_ANALYSIS_API_KEY": ("sfp_hybrid_analysis", "api_key"),
    # I Know What You Download
    "IKNOWWHATYOUDOWNLOAD_API_KEY": ("sfp_iknowwhatyoudownload", "api_key"),
    # IntelX
    "INTELX_API_KEY": ("sfp_intelx", "api_key"),
    # IP-API
    "IPAPICOM_API_KEY": ("sfp_ipapicom", "api_key"),
    # IPInfo
    "IPINFO_API_KEY": ("sfp_ipinfo", "api_key"),
    # IPQualityScore
    "IPQUALITYSCORE_API_KEY": ("sfp_ipqualityscore", "api_key"),
    # IPRegistry
    "IPREGISTRY_API_KEY": ("sfp_ipregistry", "api_key"),
    # IPStack
    "IPSTACK_API_KEY": ("sfp_ipstack", "api_key"),
    # JsonWHOIS
    "JSONWHOISCOM_API_KEY": ("sfp_jsonwhoiscom", "api_key"),
    # Koodous
    "KOODOUS_API_KEY": ("sfp_koodous", "api_key"),
    # LeakIX
    "LEAKIX_API_KEY": ("sfp_leakix", "api_key"),
    # Malware Patrol
    "MALWAREPATROL_API_KEY": ("sfp_malwarepatrol", "api_key"),
    # MetaDefender
    "METADEFENDER_API_KEY": ("sfp_metadefender", "api_key"),
    # NameAPI
    "NAMEAPI_API_KEY": ("sfp_nameapi", "api_key"),
    # NetworksDB
    "NETWORKSDB_API_KEY": ("sfp_networksdb", "api_key"),
    # NeutrinoAPI
    "NEUTRINOAPI_API_KEY": ("sfp_neutrinoapi", "api_key"),
    # Numverify
    "NUMVERIFY_API_KEY": ("sfp_numverify", "api_key"),
    # Onion.City
    "ONIONCITY_API_KEY": ("sfp_onioncity", "api_key"),
    # ONYPHE
    "ONYPHE_API_KEY": ("sfp_onyphe", "api_key"),
    # OpenCorporates
    "OPENCORPORATES_API_KEY": ("sfp_opencorporates", "api_key"),
    # Pastebin
    "PASTEBIN_API_KEY": ("sfp_pastebin", "api_key"),
    # ProjectDiscovery
    "PROJECTDISCOVERY_API_KEY": ("sfp_projectdiscovery", "api_key"),
    # Pulsedive
    "PULSEDIVE_API_KEY": ("sfp_pulsedive", "api_key"),
    # RiskIQ
    "RISKIQ_API_KEY_LOGIN": ("sfp_riskiq", "api_key_login"),
    "RISKIQ_API_KEY_PASSWORD": ("sfp_riskiq", "api_key_password"),
    # SecurityTrails
    "SECURITYTRAILS_API_KEY": ("sfp_securitytrails", "api_key"),
    # SEON
    "SEON_API_KEY": ("sfp_seon", "api_key"),
    # Shodan
    "SHODAN_API_KEY": ("sfp_shodan", "api_key"),
    # Snov.io
    "SNOV_API_KEY_CLIENT_ID": ("sfp_snov", "api_key_client_id"),
    "SNOV_API_KEY_CLIENT_SECRET": ("sfp_snov", "api_key_client_secret"),
    # Social Links
    "SOCIALLINKS_API_KEY": ("sfp_sociallinks", "api_key"),
    # Social Profiles
    "SOCIALPROFILES_BING_API_KEY": ("sfp_socialprofiles", "bing_api_key"),
    "SOCIALPROFILES_GOOGLE_API_KEY": ("sfp_socialprofiles", "google_api_key"),
    # Spur
    "SPUR_API_KEY": ("sfp_spur", "api_key"),
    # SpyOnWeb
    "SPYONWEB_API_KEY": ("sfp_spyonweb", "api_key"),
    # Stack Overflow
    "STACKOVERFLOW_API_KEY": ("sfp_stackoverflow", "api_key"),
    # TextMagic
    "TEXTMAGIC_API_KEY": ("sfp_textmagic", "api_key"),
    "TEXTMAGIC_API_KEY_USERNAME": ("sfp_textmagic", "api_key_username"),
    # ThreatJammer
    "THREATJAMMER_API_KEY": ("sfp_threatjammer", "api_key"),
    # Trash Panda
    "TRASHPANDA_API_KEY_USERNAME": ("sfp_trashpanda", "api_key_username"),
    "TRASHPANDA_API_KEY_PASSWORD": ("sfp_trashpanda", "api_key_password"),
    # Twilio
    "TWILIO_API_KEY_ACCOUNT_SID": ("sfp_twilio", "api_key_account_sid"),
    "TWILIO_API_KEY_AUTH_TOKEN": ("sfp_twilio", "api_key_auth_token"),
    # ViewDNS
    "VIEWDNS_API_KEY": ("sfp_viewdns", "api_key"),
    # VirusTotal
    "VIRUSTOTAL_API_KEY": ("sfp_virustotal", "api_key"),
    # WhatCMS
    "WHATCMS_API_KEY": ("sfp_whatcms", "api_key"),
    # Whoisology
    "WHOISOLOGY_API_KEY": ("sfp_whoisology", "api_key"),
    # Whoxy
    "WHOXY_API_KEY": ("sfp_whoxy", "api_key"),
    # WiGLE
    "WIGLE_API_KEY_ENCODED": ("sfp_wigle", "api_key_encoded"),
    # X-Force
    "XFORCE_API_KEY": ("sfp_xforce", "xforce_api_key"),
    "XFORCE_API_KEY_PASSWORD": ("sfp_xforce", "xforce_api_key_password"),
    # Zetalytics
    "ZETALYTICS_API_KEY": ("sfp_zetalytics", "api_key"),
    # Zone Files
    "ZONEFILES_API_KEY": ("sfp_zonefiles", "api_key"),
}


def load_dotenv(env_path: Path) -> dict:
    """Load environment variables from a .env file."""
    env_vars = {}
    if env_path.exists():
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, value = line.split("=", 1)
                    env_vars[key.strip()] = value.strip()
    return env_vars


def get_api_keys_from_env() -> dict:
    """Extract API keys from environment variables."""
    api_keys = {}

    # Check environment variables
    for env_suffix, (module, option) in ENV_TO_MODULE_MAP.items():
        env_var = f"SFP_{env_suffix}"
        value = os.environ.get(env_var, "")
        if value:
            if module not in api_keys:
                api_keys[module] = {}
            api_keys[module][option] = value

    return api_keys


def get_module_options_from_env() -> dict:
    """
    Extract generic module options from SFOPT_* environment variables.

    Format: SFOPT_<MODULE>_<OPTION>=value
    - MODULE: Module name without 'sfp_' prefix, uppercase, underscores preserved
    - OPTION: Option name, uppercase, converted to lowercase

    Examples:
        SFOPT__STOR_DB_MAXSTORAGE=0 -> sfp__stor_db:maxstorage=0
        SFOPT_SPIDER_MAXPAGES=100 -> sfp_spider:maxpages=100

    Note: Double underscores in module names (like sfp__stor_db) are represented
    by starting with underscore: SFOPT__STOR_DB_... -> sfp__stor_db
    """
    options = {}

    for env_var, value in os.environ.items():
        if not env_var.startswith("SFOPT_"):
            continue

        # Remove SFOPT_ prefix
        rest = env_var[6:]  # After "SFOPT_"

        if not rest or "_" not in rest:
            continue

        # Handle module names that start with underscore (like __stor_db)
        # SFOPT__STOR_DB_MAXSTORAGE -> module=__stor_db, option=maxstorage
        if rest.startswith("_"):
            # Double underscore module (e.g., __stor_db)
            # rest = "_STOR_DB_MAXSTORAGE"
            # We need to find where module ends and option begins
            # The option is typically a single word at the end
            parts = rest.split("_")
            # parts = ['', 'STOR', 'DB', 'MAXSTORAGE']
            # Module is parts[0:3] joined = "_STOR_DB" -> sfp__stor_db
            # Option is parts[3:] = "MAXSTORAGE" -> maxstorage

            # Assume option is the last segment
            if len(parts) >= 2:
                option = parts[-1].lower()
                module_part = "_".join(parts[:-1]).lower()  # "_stor_db"
                module_name = f"sfp_{module_part}"  # "sfp__stor_db"

                if option:
                    if module_name not in options:
                        options[module_name] = {}
                    options[module_name][option] = value
        else:
            # Regular module name (e.g., spider, breach_api)
            # SFOPT_SPIDER_MAXPAGES -> module=spider, option=maxpages
            # SFOPT_BREACH_API_API_URL -> module=breach_api, option=api_url
            parts = rest.split("_")

            # Assume option is the last segment for simplicity
            # For more complex cases, could try multiple split points
            if len(parts) >= 2:
                option = parts[-1].lower()
                module_part = "_".join(parts[:-1]).lower()
                module_name = f"sfp_{module_part}"

                if option:
                    if module_name not in options:
                        options[module_name] = {}
                    options[module_name][option] = value

    return options


def wait_for_database(db_path: Path, timeout: int = 60) -> bool:
    """Wait for the SpiderFoot database to exist."""
    start_time = time.time()
    while time.time() - start_time < timeout:
        if db_path.exists():
            return True
        print(f"Waiting for database at {db_path}...")
        time.sleep(2)
    return False


def get_current_config(conn: sqlite3.Connection) -> dict:
    """Get current configuration from the database."""
    cursor = conn.cursor()

    # Try to find the config table
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [row[0] for row in cursor.fetchall()]

    config = {}

    # SpiderFoot stores config in tbl_scan_config for scan-specific config
    # and module options are typically stored when scans are created
    # For global config, we need to check the actual schema

    if "tbl_config" in tables:
        cursor.execute("SELECT * FROM tbl_config")
        for row in cursor.fetchall():
            config[row[0]] = row[1] if len(row) > 1 else None

    return config


def configure_module_options(db_path: Path, api_keys: dict) -> int:
    """
    Configure module options in the SpiderFoot database.

    SpiderFoot stores module configuration in a JSON blob within the database.
    This function updates that configuration with the provided API keys.

    Returns the number of keys configured.
    """
    if not db_path.exists():
        print(f"Database not found at {db_path}")
        return 0

    conn = sqlite3.Connection(db_path)
    cursor = conn.cursor()

    # Get table list
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [row[0] for row in cursor.fetchall()]
    print(f"Found tables: {tables}")

    configured = 0

    # SpiderFoot 4.x stores global config differently
    # Check for tbl_config first
    if "tbl_config" in tables:
        # Get current config
        cursor.execute("SELECT opt, val FROM tbl_config")
        current_config = {row[0]: row[1] for row in cursor.fetchall()}

        for module, options in api_keys.items():
            for option, value in options.items():
                config_key = f"{module}:{option}"

                if config_key in current_config:
                    cursor.execute(
                        "UPDATE tbl_config SET val = ? WHERE opt = ?",
                        (value, config_key)
                    )
                else:
                    cursor.execute(
                        "INSERT INTO tbl_config (opt, val) VALUES (?, ?)",
                        (config_key, value)
                    )

                print(f"Configured: {config_key}")
                configured += 1

        conn.commit()
    else:
        print("Warning: tbl_config table not found. SpiderFoot may need to run first.")
        print("The API keys will be configured on first SpiderFoot startup via import.")

    conn.close()
    return configured


def generate_spiderfoot_cfg(api_keys: dict, output_path: Path) -> None:
    """
    Generate a spiderfoot.cfg file that can be imported via the web UI.

    This is a fallback approach if direct database seeding doesn't work.
    """
    lines = []
    for module, options in api_keys.items():
        for option, value in options.items():
            lines.append(f"{module}:{option}={value}")

    with open(output_path, "w") as f:
        f.write("\n".join(lines))

    print(f"Generated {output_path} with {len(lines)} API keys")


def get_csrf_token(base_url: str) -> str:
    """Get CSRF token from SpiderFoot settings page."""
    if not requests:
        raise ImportError("requests library required for API import")

    response = requests.get(f"{base_url}/opts", timeout=10)
    response.raise_for_status()

    # Extract token from page - look for: var defined_token = 'xxx';
    import re
    match = re.search(r"var\s+token\s*=\s*['\"]([^'\"]+)['\"]", response.text)
    if not match:
        # Try alternate pattern
        match = re.search(r"name=['\"]token['\"].*?value=['\"]([^'\"]+)['\"]", response.text)
    if not match:
        # Try hidden input
        match = re.search(r"id=['\"]token['\"].*?value=['\"]([^'\"]+)['\"]", response.text)

    if match:
        return match.group(1)

    raise ValueError("Could not find CSRF token in settings page")


def import_config_via_api(base_url: str, cfg_path: Path) -> bool:
    """
    Import API keys configuration via SpiderFoot web API.

    Args:
        base_url: SpiderFoot base URL (e.g., http://localhost:5001)
        cfg_path: Path to spiderfoot.cfg file

    Returns:
        True if import was successful
    """
    if not requests:
        print("Error: requests library required for API import")
        print("Install with: pip install requests")
        return False

    if not cfg_path.exists():
        print(f"Error: Config file not found: {cfg_path}")
        return False

    try:
        # Get CSRF token
        print(f"Connecting to {base_url}...")
        token = get_csrf_token(base_url)
        print(f"Got CSRF token: {token[:8]}...")

        # Read config file
        with open(cfg_path, "rb") as f:
            cfg_content = f.read()

        # Submit the form with file upload
        files = {
            "configFile": ("spiderfoot.cfg", cfg_content, "text/plain")
        }
        data = {
            "allopts": "",
            "token": token
        }

        print("Importing API keys...")
        response = requests.post(
            f"{base_url}/savesettings",
            data=data,
            files=files,
            timeout=30,
            allow_redirects=False
        )

        # Success is indicated by a redirect to /opts
        if response.status_code in (302, 303) or response.status_code == 200:
            print("API keys imported successfully!")
            return True
        else:
            print(f"Import may have failed. Status: {response.status_code}")
            return False

    except requests.exceptions.ConnectionError:
        print(f"Error: Could not connect to {base_url}")
        print("Make sure SpiderFoot is running")
        return False
    except Exception as e:
        print(f"Error importing config: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Configure SpiderFoot API keys and module options from environment variables"
    )
    parser.add_argument(
        "--db-path",
        type=Path,
        default=Path("/var/lib/spiderfoot/spiderfoot.db"),
        help="Path to SpiderFoot database"
    )
    parser.add_argument(
        "--env-file",
        type=Path,
        default=Path(".env"),
        help="Path to .env file"
    )
    parser.add_argument(
        "--generate-cfg",
        type=Path,
        help="Generate spiderfoot.cfg file for manual import"
    )
    parser.add_argument(
        "--wait",
        action="store_true",
        help="Wait for database to exist before configuring"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=60,
        help="Timeout in seconds when waiting for database"
    )
    parser.add_argument(
        "--import",
        dest="do_import",
        action="store_true",
        help="Import config via SpiderFoot web API"
    )
    parser.add_argument(
        "--url",
        default="http://localhost:5001",
        help="SpiderFoot base URL (default: http://localhost:5001)"
    )

    args = parser.parse_args()

    # Load .env file if it exists
    if args.env_file.exists():
        env_vars = load_dotenv(args.env_file)
        for key, value in env_vars.items():
            if key not in os.environ:
                os.environ[key] = value
        print(f"Loaded {len(env_vars)} variables from {args.env_file}")

    # Get API keys from environment
    api_keys = get_api_keys_from_env()

    # Get generic module options from environment
    module_options = get_module_options_from_env()

    # Merge API keys and module options
    all_config = {}
    for module, options in api_keys.items():
        if module not in all_config:
            all_config[module] = {}
        all_config[module].update(options)

    for module, options in module_options.items():
        if module not in all_config:
            all_config[module] = {}
        all_config[module].update(options)

    if not all_config:
        print("No configuration found in environment variables")
        print("Set variables like:")
        print("  SFP_SHODAN_API_KEY=your_key (API keys)")
        print("  SFOPT__STOR_DB_MAXSTORAGE=0 (module options)")
        sys.exit(0)

    if api_keys:
        print(f"Found API keys for {len(api_keys)} modules:")
        for module in api_keys:
            print(f"  - {module}: {len(api_keys[module])} option(s)")

    if module_options:
        print(f"Found module options for {len(module_options)} modules:")
        for module, opts in module_options.items():
            for opt, val in opts.items():
                print(f"  - {module}:{opt}={val}")

    # Generate spiderfoot.cfg if requested
    if args.generate_cfg:
        generate_spiderfoot_cfg(all_config, args.generate_cfg)

    # Configure database
    if args.wait:
        if not wait_for_database(args.db_path, args.timeout):
            print(f"Timeout waiting for database at {args.db_path}")
            # Generate cfg file as fallback
            cfg_path = args.db_path.parent / "spiderfoot.cfg"
            generate_spiderfoot_cfg(all_config, cfg_path)
            print(f"Generated {cfg_path} for manual import")
            sys.exit(1)

    if args.db_path.exists() and not args.do_import:
        # Only try database approach if we're not using API import
        try:
            configured = configure_module_options(args.db_path, all_config)
            print(f"Configured {configured} option(s) in database")
        except Exception as e:
            print(f"Database configuration failed: {e}")
            print("Will use API import if --import flag is set")
    elif not args.do_import:
        print(f"Database not found at {args.db_path}")
        # Generate cfg file as fallback
        cfg_path = Path("spiderfoot.cfg")
        generate_spiderfoot_cfg(all_config, cfg_path)
        print(f"Generated {cfg_path} for manual import after SpiderFoot starts")

    # Import via API if requested
    if args.do_import:
        # Determine config file path
        if args.generate_cfg:
            cfg_path = args.generate_cfg
        else:
            cfg_path = args.db_path.parent / "spiderfoot.cfg"
            if not cfg_path.exists():
                cfg_path = Path("spiderfoot.cfg")

        if cfg_path.exists():
            success = import_config_via_api(args.url, cfg_path)
            sys.exit(0 if success else 1)
        else:
            print(f"No config file found to import")
            sys.exit(1)


if __name__ == "__main__":
    main()
