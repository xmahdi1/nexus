"""Read supported local proxy configuration and emit only route metadata."""

import ipaddress
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import sys
from urllib.parse import urlsplit

MAX_FILES = 64
MAX_FILE_BYTES = 256 * 1024
MAX_ROUTES = 256
MAX_CERTIFICATES = 32
MAX_CERT_BYTES = 12 * 1024
LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
PATH = re.compile(r"/[a-zA-Z0-9_.~/*-]{0,255}")
NGINX_TOKEN = re.compile(
    r"""\s+|\#[^\n]*|[{};]|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'"""
    r"""|(?:\$\{[^}\n]*\}|\\.|[^\s{};\#"'\\])+|."""
)


def read_config(path, parents):
    actual = path.resolve(strict=True)
    if actual.parent not in parents:
        raise ValueError("unsupported config location")
    fd = os.open(actual, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            raise ValueError("unsupported config file")
        raw = f.read(MAX_FILE_BYTES + 1)
    if len(raw) > MAX_FILE_BYTES or b"\x00" in raw:
        raise ValueError("invalid config size")
    return raw.decode("utf-8")


def unquote(value):
    if len(value) >= 2 and value[0] in "\"'" and value[0] == value[-1]:
        return value[1:-1]
    return value


def nginx_tokens(text):
    for match in NGINX_TOKEN.finditer(text):
        token = match[0]
        if token.isspace() or token.startswith("#"):
            continue
        if token in ('"', "'", "\\"):
            raise ValueError("invalid config token")
        yield token


def caddy_tokens(text):
    for line in text.splitlines():
        words = shlex.split(line, comments=True)
        if any(word.startswith("<<") for word in words):
            raise ValueError("unsupported config syntax")
        yield from words
        yield "\n"


def blocks(tokens, separator):
    root = []
    stack = [root]
    words = []
    for token in tokens:
        if token == "{":
            if len(stack) >= 24:
                raise ValueError("config nesting limit")
            children = []
            stack[-1].append((words, children))
            stack.append(children)
        elif token == "}":
            if len(stack) == 1 or (words and separator != "\n"):
                raise ValueError("invalid config block")
            if words:
                stack[-1].append((words, None))
            stack.pop()
        elif token == separator:
            if words:
                stack[-1].append((words, None))
        else:
            words.append(unquote(token))
            continue
        words = []
    if len(stack) != 1 or words:
        raise ValueError("unfinished config block")
    return root


def hostname(value, allow_wildcard=True):
    value = value.lower().rstrip(".")
    try:
        return str(ipaddress.ip_address(value)) if "%" not in value else ""
    except ValueError:
        pass
    suffix = value[2:] if allow_wildcard and value.startswith("*.") else value
    if len(value) <= 253 and all(LABEL.fullmatch(label) for label in suffix.split(".")):
        return value
    return ""


def port(value):
    if re.fullmatch(r"[0-9]{1,5}", value) and 0 < int(value) <= 65535:
        return int(value)
    return 0


def url_parts(value, default_scheme):
    try:
        parsed = urlsplit(value if "://" in value else default_scheme + "://" + value)
        host = hostname(parsed.hostname or "", allow_wildcard=False)
        if parsed.username is not None or parsed.password is not None:
            return None
        if host and parsed.scheme in ("http", "https") and parsed.port != 0:
            return parsed.scheme, host, parsed.port, parsed.path
    except ValueError:
        pass
    return None


def upstream(value, require_scheme):
    if require_scheme and "://" not in value:
        return ""
    parsed = url_parts(value, "http")
    if not parsed or any(char in value for char in ("$", "{", "}")):
        return ""
    scheme, host, explicit, _ = parsed
    address = "[" + host + "]" if ":" in host else host
    default = 443 if scheme == "https" else 80
    return f"{scheme}://{address}:{explicit or default}"


def route(host, path, match, listen, tls, targets, certificate_files):
    return dict(host=host, path=path, match=match, port=listen, tls=tls,
                upstreams=sorted(set(targets)), certificate_files=certificate_files)


def nginx_server(directives):
    hosts, listeners, locations, certificate_files = [], set(), [], []
    complete = True
    for words, children in directives:
        if not words:
            continue
        directive, args = words[0], words[1:]
        if directive == "server_name":
            hosts.extend(filter(None, (hostname(value) for value in args)))
        elif directive == "listen" and args:
            listen = port(args[0].rsplit(":", 1)[-1])
            if listen and not args[0].startswith("unix:") and "quic" not in args:
                listeners.add((listen, "ssl" in args))
            else:
                complete = False
        elif directive == "location" and children is not None:
            locations.append((args, children))
        elif directive == "ssl_certificate" and len(args) == 1 and len(certificate_files) < 8:
            certificate_files.append(args[0])
        elif directive == "include":
            complete = False
    if not listeners:
        listeners = {(80, False)} if not any(w and w[0] == "listen" for w, _ in directives) else set()
    rows = []
    for args, children in locations:
        proxies = [w for w, _ in children if w and w[0] == "proxy_pass"]
        if any(w and (w[0] in ("include", "location") or (w[0] == "if" and block is not None))
               for w, block in children):
            complete = False
        if not proxies:
            continue
        exact = len(args) == 2 and args[0] == "="
        path = args[-1] if args else ""
        if (not exact and len(args) != 1) or not PATH.fullmatch(path) or len(proxies) != 1 or len(proxies[0]) != 2:
            complete = False
            continue
        target = upstream(proxies[0][1], require_scheme=True)
        if not target or not hosts:
            complete = False
            continue
        for host in sorted(set(hosts)):
            for listen, tls in sorted(listeners):
                if len(rows) >= MAX_ROUTES:
                    return rows, False
                rows.append(route(host, path, "exact" if exact else "prefix", listen, tls, [target], certificate_files))
    return rows, complete


def nginx_config(text):
    config = blocks(nginx_tokens(text), ";")
    sections = list(config)
    for words, child in config:
        if words == ["http"] and child is not None:
            sections.extend(child)
    rows, complete = [], True
    for words, child in sections:
        if words == ["server"] and child is not None:
            batch, complete_server = nginx_server(child)
            rows.extend(batch)
            complete = complete and complete_server
            if len(rows) >= MAX_ROUTES:
                return rows[:MAX_ROUTES], False
    return rows, complete


def caddy_address(value, default_ports):
    try:
        parsed = urlsplit(value if "://" in value else "https://" + value)
        host = hostname(parsed.hostname or "")
        if not host or parsed.path or parsed.query or parsed.fragment or parsed.username is not None or parsed.port == 0:
            return None
        scheme = parsed.scheme
        if "://" not in value and parsed.port == default_ports["http"]:
            scheme = "http"
        if scheme in default_ports:
            return host, parsed.port or default_ports[scheme], scheme == "https"
    except ValueError:
        pass
    return None


def caddy_config(text):
    tokens = list(caddy_tokens(text))
    if "{" not in tokens and tokens:
        while tokens and tokens[0] == "\n":
            tokens.pop(0)
        if tokens and "\n" in tokens:
            tokens[tokens.index("\n")] = "{"
            tokens.append("}")
    config = blocks(tokens, "\n")
    default_ports = {"http": 80, "https": 443}
    if config and config[0][0] == [] and config[0][1] is not None:
        for words, _ in config[0][1]:
            if len(words) == 2 and words[0] in ("http_port", "https_port"):
                listen = port(words[1])
                if not listen:
                    raise ValueError("invalid configured listener")
                default_ports[words[0][:-5]] = listen
    rows, complete = [], True
    for words, child in config:
        if not words:
            continue
        if child is None or words[0].startswith(("(", "&")):
            if words[0] == "import":
                complete = False
            continue
        addresses = [caddy_address(value, default_ports) for value in " ".join(words).replace(",", " ").split()]
        certificate_files = [d[1] for d, _ in child if len(d) == 3 and d[0] == "tls"][:8]
        for directive, nested in child:
            if not directive:
                continue
            if directive[0] != "reverse_proxy":
                if directive[0] == "import" or nested:
                    complete = False
                continue
            args, path = directive[1:], "/*"
            if args and args[0].startswith("/"):
                path, args = args[0], args[1:]
            targets = [upstream(value, require_scheme=False) for value in args]
            if (not PATH.fullmatch(path) or not targets or len(targets) > 8 or not all(targets)
                    or (nested and any(w and w[0] in ("dynamic", "to") for w, _ in nested))):
                complete = False
                continue
            for address in addresses:
                if not address:
                    complete = False
                    continue
                host, listen, tls = address
                if len(rows) >= MAX_ROUTES:
                    return rows, False
                rows.append(route(host, path, "caddy", listen, tls, targets, certificate_files))
    return rows, complete


def collect(engine, etc):
    if engine == "nginx":
        base = etc / "nginx"
        candidates = [base / "nginx.conf"]
        parents = {base, base / "sites-enabled", base / "sites-available", base / "conf.d"}
        for directory in (base / "sites-enabled", base / "conf.d"):
            try:
                for path in directory.iterdir():
                    if path.name.startswith(".") or (directory.name == "conf.d" and path.suffix != ".conf"):
                        continue
                    candidates.append(path)
                    if len(candidates) > MAX_FILES:
                        return [], False
            except FileNotFoundError:
                pass
        parser = nginx_config
    else:
        base = etc / "caddy"
        candidates, parents, parser = [base / "Caddyfile"], {base}, caddy_config
    rows, complete = [], True
    for path in sorted(candidates):
        try:
            found, covered = parser(read_config(path, parents))
        except FileNotFoundError:
            # A missing entry point without a symlink is a normal absent proxy.
            complete = complete and path.name in ("nginx.conf", "Caddyfile") and not path.is_symlink()
            continue
        except (OSError, ValueError):
            complete = False
            continue
        rows.extend(found)
        complete = complete and covered
        if len(rows) > MAX_ROUTES:
            return rows[:MAX_ROUTES], False
    return rows, complete


def read_certificate(path, roots):
    actual = path.resolve(strict=True)
    if not any(root in actual.parents for root in roots):
        raise ValueError("unsupported certificate location")
    fd = os.open(actual, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            raise ValueError("unsupported certificate file")
        if f.readline(64).strip() != b"-----BEGIN CERTIFICATE-----":
            raise ValueError("certificate PEM required")
        value, end, _ = f.read(MAX_CERT_BYTES + 1).partition(b"-----END CERTIFICATE-----")
    if not end or len(value) > MAX_CERT_BYTES:
        raise ValueError("certificate length")
    raw = base64.b64decode(b"".join(value.split()), validate=True)
    return base64.b64encode(raw).decode("ascii")


def caddy_cache_files(host, cache_roots):
    for root in cache_roots:
        try:
            for index, issuer in enumerate(root.iterdir()):
                if index >= 16:
                    raise ValueError("certificate issuer directory limit")
                path = issuer / host / (host + ".crt")
                if path.is_file():
                    yield path
        except FileNotFoundError:
            continue


def certificates(engine, routes, etc, cache_roots):
    roots = {etc / "ssl", etc / "letsencrypt", etc / engine}
    if engine == "caddy":
        roots.update(cache_roots)
    seen, records, complete = set(), [], True
    for row in routes:
        file_names = row.pop("certificate_files")
        if not row["tls"]:
            continue
        host, listen = row["host"], row["port"]
        files = [Path(name) for name in file_names if Path(name).is_absolute()]
        if not file_names and engine == "caddy" and "*" not in host and ":" not in host:
            try:
                files = list(caddy_cache_files(host, cache_roots))
            except (OSError, ValueError):
                complete = False
        if not files or (file_names and len(file_names) != len(files)):
            complete = False
        for path in files:
            key = (host, listen, path)
            if key in seen:
                continue
            seen.add(key)
            if len(seen) > MAX_CERTIFICATES:
                complete = False
                continue
            try:
                der = read_certificate(path, roots)
            except (OSError, ValueError):
                complete = False
                continue
            slot = hashlib.sha256(os.fsencode(path)).hexdigest()
            records.append(dict(host=host, port=listen, slot=slot, der=der))
    return records, complete


if __name__ == "__main__":
    engine = sys.argv[1]
    assert engine in ("nginx", "caddy")
    try:
        routes, complete = collect(engine, Path("/etc"))
    except (OSError, ValueError):
        routes, complete = [], False
    cache = (Path.home() / ".local/share/caddy/certificates",
             Path("/var/lib/caddy/.local/share/caddy/certificates"))
    certs, tls_complete = certificates(engine, routes, Path("/etc"), tuple(dict.fromkeys(cache)))
    print(json.dumps({"routes": routes, "complete": complete,
                      "certificates": certs, "tlsComplete": tls_complete and complete},
                     separators=(",", ":")))
