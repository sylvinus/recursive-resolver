"""Command-line interface for recursive-resolver."""

from __future__ import annotations

import argparse
import json
import logging
import sys

from . import Answer, RecursiveResolver, ResolverError, ValidationState, __version__
from .resolver import DEFAULT_EDNS_PAYLOAD

# Wording follows delv, BIND's validating lookup utility, so the states read the
# same across tools. delv prints these on stdout, but it emits full records;
# our plain output is bare values, so the note goes to stderr and stdout stays
# pipeable. "2>/dev/null" is then an explicit opt-out.
_DNSSEC_NOTES = {
    ValidationState.SECURE: "; fully validated",
    ValidationState.INSECURE: "; unsigned answer",
    ValidationState.BOGUS: "; validation failed",
}


def _note_dnssec(answer: Answer, args: argparse.Namespace) -> None:
    """Report the DNSSEC verdict on stderr, so plain output is not silently unvalidated.

    Only for the plain output paths; the JSON payload carries the state itself.
    """
    if args.no_dnssec:
        # Without this the default Answer state would render as "unsigned
        # answer", which claims a proof we never went looking for.
        print("; dnssec validation disabled", file=sys.stderr)
        return
    print(_DNSSEC_NOTES[answer.dnssec], file=sys.stderr)


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="recursive-resolver",
        description="Resolve DNS records iteratively from the root servers, with DNSSEC validation.",
    )
    parser.add_argument("domain", help="Domain name to resolve (or IP for PTR)")
    parser.add_argument(
        "rdtype",
        nargs="?",
        default="A",
        help="Record type: A, AAAA, MX, TXT, NS, SOA, PTR, CNAME, SRV, CAA, ... (default: A)",
    )
    parser.add_argument("--trace", action="store_true", help="Show the full delegation trace")
    parser.add_argument("--json", action="store_true", dest="json_output", help="Output results as JSON")
    parser.add_argument(
        "--text",
        action="store_true",
        help="Print TXT-like records as concatenated character-strings (correct for DKIM/SPF)",
    )
    parser.add_argument("--timeout", type=float, default=2.0, help="Per-query timeout in seconds (default: 2.0)")
    parser.add_argument("--max-depth", type=int, default=20, help="Maximum delegation depth (default: 20)")
    parser.add_argument(
        "--max-time", type=float, default=15.0, help="Max total resolution time in seconds (default: 15.0)"
    )
    parser.add_argument(
        "--edns-payload",
        type=int,
        default=DEFAULT_EDNS_PAYLOAD,
        help=f"Advertised EDNS0 UDP payload size (default: {DEFAULT_EDNS_PAYLOAD})",
    )
    parser.add_argument("--no-cache", action="store_true", help="Disable all caching")
    parser.add_argument(
        "--no-cache-answers",
        action="store_true",
        help="Do not cache answers (keeps delegation caching, for maximum freshness)",
    )
    parser.add_argument(
        "--cache-depth",
        default=None,
        metavar="LEVEL",
        help="How deep to cache zone cuts: tld, all, none, or a label depth",
    )
    parser.add_argument("--no-dnssec", action="store_true", help="Disable DNSSEC validation")
    parser.add_argument("--require-dnssec", action="store_true", help="Fail unless the answer is DNSSEC-authenticated")
    parser.add_argument(
        "--allow-private",
        action="store_true",
        help="Allow private/loopback nameserver addresses (split-horizon DNS only)",
    )
    parser.add_argument("--ipv6", action="store_true", help="Enable IPv6 for queries (default: IPv4 only)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point for the recursive-resolver CLI."""
    args = build_parser().parse_args(argv)

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG, format="%(name)s %(levelname)s %(message)s", stream=sys.stderr)

    try:
        resolver = RecursiveResolver(
            timeout=args.timeout,
            max_depth=args.max_depth,
            cache_enabled=not args.no_cache,
            cache_answers=not args.no_cache_answers,
            max_delegation_cache_depth=args.cache_depth,
            ipv4_only=not args.ipv6,
            max_resolution_time=args.max_time,
            edns_payload=args.edns_payload,
            dnssec=not args.no_dnssec,
            require_dnssec=args.require_dnssec,
            allow_private_addresses=args.allow_private,
        )
    except (ResolverError, ValueError) as exc:
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return 2

    try:
        if args.trace:
            return _run_trace(resolver, args)
        return _run_query(resolver, args)
    except ResolverError as exc:
        if args.json_output:
            print(json.dumps({"error": type(exc).__name__, "message": str(exc)}), file=sys.stderr)
        else:
            print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


def _run_query(resolver: RecursiveResolver, args: argparse.Namespace) -> int:
    answer = resolver.resolve_answer(args.domain, args.rdtype)
    if args.text:
        try:
            values = answer.text_values()
        except TypeError as exc:
            print(f"--text: {exc}", file=sys.stderr)
            return 2
    else:
        values = answer.records

    if args.json_output:
        print(
            json.dumps(
                {
                    "qname": str(answer.qname),
                    "canonical_name": str(answer.canonical_name),
                    "records": values,
                    "ttl": answer.ttl,
                    "dnssec": answer.dnssec.value,
                },
                indent=2,
            )
        )
    else:
        _note_dnssec(answer, args)
        for value in values:
            print(value)
    return 0


def _run_trace(resolver: RecursiveResolver, args: argparse.Namespace) -> int:
    answer, trace = resolver.trace_answer(args.domain, args.rdtype)
    if args.json_output:
        payload = {
            "trace": [
                {
                    "server": step.server,
                    "qname": step.qname,
                    "rdtype": step.rdtype,
                    "response_type": step.response_type,
                    "detail": step.detail,
                    "rcode": step.rcode,
                    "zone": step.zone,
                    "dnssec": step.dnssec,
                }
                for step in trace
            ],
            "records": answer.records if answer else None,
            "dnssec": answer.dnssec.value if answer else None,
        }
        print(json.dumps(payload, indent=2))
    else:
        for step in trace:
            print(f"{step.server:20s} {step.qname:30s} {step.response_type:10s} {step.dnssec:9s} {step.detail}")
        if answer is not None:
            _note_dnssec(answer, args)
            for record in answer.records:
                print(record)
    if answer is None:
        last = trace[-1].response_type if trace else "no response"
        print(f"Resolution failed after {len(trace)} step(s); last response: {last}", file=sys.stderr)
        return 1
    return 0
