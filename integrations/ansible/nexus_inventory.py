#!/usr/bin/env python3
"""Ansible script inventory. Fetch fresh authorized targets on every invocation.

NEXUS_URL: HTTPS Nexus origin (loopback HTTP allowed for local fixtures).
NEXUS_INVENTORY_TOKEN_FILE: private file containing a short-lived inventory token.
Never accepts Nexus login cookies or SSH secrets. No persistent cache or redirects.
"""

import argparse
import ipaddress
import json
import os
import re
import ssl
import stat
import sys
import urllib.error
import urllib.parse
import urllib.request

MAX_BYTES = 2 * 1024 * 1024


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("Inventory redirects are not accepted")


def fetch():
    url = urllib.parse.urlsplit(os.environ.get("NEXUS_URL", ""))
    if url.username or url.password or url.query or url.fragment or url.path not in ("", "/"):
        raise ValueError("NEXUS_URL must be an origin without credentials, path or query")
    loopback = url.hostname == "localhost"
    try:
        loopback = loopback or ipaddress.ip_address(url.hostname).is_loopback
    except ValueError:
        pass
    if not url.hostname or (url.scheme != "https" and not (url.scheme == "http" and loopback)):
        raise ValueError("Use HTTPS, or loopback HTTP for local fixtures")
    path = os.environ["NEXUS_INVENTORY_TOKEN_FILE"]
    # Reject symlinks and oversized/public credentials before reading them.
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "r") as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_size > 128:
            raise ValueError("Inventory token file must be private, regular and owned by this user")
        token = source.read(129).strip()
    if not re.fullmatch(r"nxi_[a-f0-9]{64}", token):
        raise ValueError("Invalid inventory token file")
    request = urllib.request.Request(urllib.parse.urlunsplit((url.scheme, url.netloc, "/api/automation/ansible/inventory", "", "")), headers={"Authorization": "Bearer " + token, "Accept": "application/json"})
    # Explicit proxy exclusion avoids forwarding credentials to ambient proxy
    # configuration. HTTPS still uses the system CA bundle and verifies names.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    with opener.open(request, timeout=15) as response:
        if response.status != 200 or response.headers.get_content_type() != "application/json":
            raise ValueError("Unexpected inventory response")
        data = response.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("Inventory response exceeds size limit")
    result = json.loads(data)
    if not isinstance(result, dict) or not isinstance(result.get("_meta", {}).get("hostvars"), dict):
        raise ValueError("Invalid inventory response")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--list", action="store_true")
    action.add_argument("--host")
    parser.add_argument("--refresh", action="store_true", help="Every invocation already refreshes inventory")
    args = parser.parse_args()
    try:
        inventory = fetch()
        result = inventory if args.list else inventory["_meta"]["hostvars"].get(args.host, {})
        print(json.dumps(result, separators=(",", ":")))
    except (OSError, ValueError, KeyError, TypeError, urllib.error.URLError):
        # Never print a server response, credential, address or traceback.
        print("Nexus inventory unavailable; check the connection, token lifetime and current permissions.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
