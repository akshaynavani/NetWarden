"""DNS server probe: queries the host directly for configured records."""

from __future__ import annotations

import time
from typing import Any

import dns.asyncresolver
import dns.exception
import dns.resolver

from netwarden.config import DnsRecordCheck, Host
from netwarden.models import ProbeStatus
from netwarden.probes.base import Probe


def normalise_answer(rdtype: str, text: str) -> str:
    text = text.strip().rstrip(".").lower()
    if rdtype == "TXT":
        text = text.strip('"')
    if rdtype == "MX":
        # "10 mail.example.com" -> keep both parts, normalised
        parts = text.split()
        text = " ".join(parts)
    return text


def compare_answers(rdtype: str, expected: list[str], actual: list[str]) -> dict[str, list[str]]:
    exp = {normalise_answer(rdtype, e) for e in expected}
    act = {normalise_answer(rdtype, a) for a in actual}
    return {"missing": sorted(exp - act), "unexpected": sorted(act - exp) if exp else []}


class DnsProbe(Probe):
    name = "dns"

    def _resolver(self, host: Host) -> dns.asyncresolver.Resolver:
        resolver = dns.asyncresolver.Resolver(configure=False)
        resolver.nameservers = [host.address]
        resolver.port = host.checks.dns.port if host.checks.dns else 53
        resolver.lifetime = max(1.0, self.config.polling.probe_timeout_seconds / 2)
        resolver.timeout = resolver.lifetime
        return resolver

    async def _query(
        self, resolver: dns.asyncresolver.Resolver, record: DnsRecordCheck
    ) -> dict[str, Any]:
        started = time.perf_counter()
        try:
            answer = await resolver.resolve(record.name, record.type, raise_on_no_answer=False)
        except dns.resolver.NXDOMAIN:
            return {"ok": False, "rcode": "NXDOMAIN", "answers": []}
        except dns.resolver.NoNameservers as exc:
            return {"ok": False, "rcode": "SERVFAIL", "answers": [], "error": str(exc)}
        except dns.exception.Timeout:
            return {"ok": False, "rcode": "TIMEOUT", "answers": []}
        latency = round((time.perf_counter() - started) * 1000, 2)
        answers = [r.to_text() for r in answer] if answer.rrset else []
        diff = compare_answers(record.type, record.expect, answers)
        ok = bool(answers) and not diff["missing"]
        return {
            "ok": ok,
            "rcode": "NOERROR",
            "answers": answers,
            "latency_ms": latency,
            **diff,
        }

    async def collect(self, host: Host) -> tuple[ProbeStatus, dict[str, Any]]:
        check = host.checks.dns
        assert check is not None
        if not check.records:
            return ProbeStatus.SKIPPED, {}
        resolver = self._resolver(host)
        records: dict[str, Any] = {}
        for record in check.records:
            records[f"{record.name}/{record.type}"] = await self._query(resolver, record)
        if all(r["rcode"] == "TIMEOUT" for r in records.values()):
            status = ProbeStatus.UNREACHABLE
        elif all(r["ok"] for r in records.values()):
            status = ProbeStatus.OK
        else:
            status = ProbeStatus.ERROR
        latencies = [r["latency_ms"] for r in records.values() if "latency_ms" in r]
        metrics = {
            "records": records,
            "max_latency_ms": max(latencies) if latencies else None,
        }
        return status, metrics
