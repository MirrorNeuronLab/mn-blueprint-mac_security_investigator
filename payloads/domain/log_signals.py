"""Recognize specific security log signals without retaining message contents."""

from dataclasses import dataclass
import re


ASSESSMENTS = {
    "gatekeeper_block": {
        "title": "Gatekeeper reported a block",
        "confidence": "High",
        "assessment": "macOS logged a blocked security assessment. This can happen during an expected installation, update, or app launch.",
        "next_step": "Compare the evidence time with recent installations and app launches.",
    },
    "signature_failure": {
        "title": "Application integrity validation failed",
        "confidence": "High",
        "assessment": "The application integrity service logged a validation failure. An invalid signature, trust configuration, or provisioning issue can cause this.",
        "next_step": "Check whether the time matches an expected app update or launch.",
    },
    "security_service_fault": {
        "title": "A security service reported a fault",
        "confidence": "Limited",
        "assessment": "A watched security service emitted a fault-level log. The available evidence leaves its cause and impact unknown.",
        "next_step": "Review related messages in Console around the evidence time if the fault recurs.",
    },
}

@dataclass(frozen=True)
class LogRule:
    signal: str
    indicator: str
    fragment: str
    pattern: re.Pattern


def _rule(signal, indicator, fragment, *, prefix="", suffix=""):
    pattern = re.compile("^" + prefix + re.escape(fragment) + suffix, re.IGNORECASE)
    return LogRule(signal, indicator, fragment, pattern)


_PROCESS_RULES = {
    "/usr/libexec/syspolicyd": (
        _rule("gatekeeper_block", "Gatekeeper rejection",
              "Terminating process due to Gatekeeper rejection:"),
        _rule("gatekeeper_block", "Gatekeeper evaluation reported was allowed = 0",
              "GK eval - was allowed: 0", suffix=r"(?:,|$)"),
    ),
    "/usr/libexec/amfid": (
        _rule("signature_failure", "Signature validation failed",
              "signature validation failed", prefix=r"(?:AMFI: )?(?:code )?", suffix=r"\b"),
        _rule("signature_failure", "Trust or authorization validation failed",
              "validation failed because of missing trust and/or authorization", suffix=r"\b"),
        _rule("signature_failure", "Application integrity service returned an invalid-code error",
              " not valid: Error Domain=AppleMobileFileIntegrityError Code=",
              prefix=r"(?:<private>|/[^:\r\n]*)", suffix=r"-?\d+\b"),
    ),
}

PROCESSES = tuple(image.rsplit("/", 1)[-1] for image in _PROCESS_RULES)
MESSAGE_FRAGMENTS = tuple(rule.fragment for rules in _PROCESS_RULES.values() for rule in rules)


def signal_for(image, message, level):
    rules = _PROCESS_RULES.get(image)
    if rules is None:
        return None
    # Retain only authored indicator text. Message arguments never enter evidence.
    if isinstance(message, str):
        for rule in rules:
            if rule.pattern.match(message):
                return rule.signal, rule.indicator
    if level == "Fault":
        return "security_service_fault", "macOS fault-level event"
    return None
