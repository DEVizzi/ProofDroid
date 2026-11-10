"""Verification checks. Add a new check by writing a module with a `Check`
subclass and registering it in `default_checks()`."""

from __future__ import annotations

from ..models import Finding
from .base import Check, CheckContext
from .data_exposure import CleartextTrafficCheck, InsecureStorageCheck, LeakedSecretsCheck
from .exported_provider import ExportedProviderCheck
from .exported_components import ExportedActivityCheck, ExportedReceiverCheck, ExportedServiceCheck
from .frida_trustmanager import TrustManagerFridaCheck

__all__ = ["Check", "CheckContext", "default_checks", "find_check"]


def default_checks() -> list[Check]:
    return [
        ExportedActivityCheck(), ExportedServiceCheck(), ExportedReceiverCheck(), ExportedProviderCheck(),
        CleartextTrafficCheck(), InsecureStorageCheck(), LeakedSecretsCheck(), TrustManagerFridaCheck(),
    ]


def find_check(finding: Finding, checks: list[Check]) -> Check | None:
    return next((c for c in checks if c.applies(finding)), None)
