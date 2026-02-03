"""Command-line interface for recursive-resolver (DNS recursive resolution from root servers)."""

from __future__ import annotations

import argparse
import json
import logging
import sys

from . import RecursiveResolver, ResolverError, __version__


def main(argv: list[str] | None = None) -> int:
    """Entry point for the recursive-resolver CLI."""
    parser = argparse.ArgumentParser(
        prog="recursive-resolver",
        description="Resolve DNS records iteratively from root servers.",
    )
    parser.add_argument("domain", help="Domain name to resolve (or IP for PTR)")
    parser.add_argument(
        "rdtype",
        nargs="?",
        default="A",
        help="Record type: A, AAAA, MX, TXT, NS, SOA, PTR, CNAME, SRV, CAA, ... (default: A)",
    )
    parser.add_argument(
        "--trace",
        action="store_true",
        help="Show the full delegation trace",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Output results as JSON",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="Per-query timeout in seconds (default: 5.0)",
    )
    parser.add_argument(
        "--max-depth",
        type=int,
        default=20,
        help="Maximum delegation depth (default: 20)",
    )
    parser.add_argument(
        "--max-time",
        type=float,
        default=30.0,
        help="Max total resolution time in seconds (default: 30.0)",
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Disable response caching",
    )
    parser.add_argument(
        "--ipv6",
        action="store_true",
        help="Enable IPv6 for queries (default: IPv4 only)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable debug logging",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    args = parser.parse_args(argv)

    if args.verbose:
        logging.basicConfig(
            level=logging.DEBUG,
            format="%(name)s %(levelname)s %(message)s",
            stream=sys.stderr,
        )

    resolver = RecursiveResolver(
        timeout=args.timeout,
        max_depth=args.max_depth,
        cache_enabled=not args.no_cache,
        ipv4_only=not args.ipv6,
        max_resolution_time=args.max_time,
    )

    try:
        if args.trace:
            trace = resolver.resolve_with_trace(args.domain, args.rdtype)
            if args.json_output:
                data = [
                    {
                        "server": step.server,
                        "qname": step.qname,
                        "rdtype": step.rdtype,
                        "response_type": step.response_type,
                        "detail": step.detail,
                        "rcode": step.rcode,
                    }
                    for step in trace
                ]
                print(json.dumps(data, indent=2))
            else:
                for step in trace:
                    print(f"{step.server:20s} {step.qname:30s} {step.response_type:10s} {step.detail}")
        else:
            answers = resolver.resolve(args.domain, args.rdtype)
            if args.json_output:
                print(json.dumps(answers, indent=2))
            else:
                for answer in answers:
                    print(answer)
    except ResolverError as e:
        if args.json_output:
            print(json.dumps({"error": type(e).__name__, "message": str(e)}), file=sys.stderr)
        else:
            print(f"{type(e).__name__}: {e}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
