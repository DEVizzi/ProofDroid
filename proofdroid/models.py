"""Core data models shared across the pipeline."""

from __future__ import annotations

import enum
from dataclasses import asdict, dataclass, field

# Finding categories. Checks declare which categories they can verify.
EXPORTED_ACTIVITY = "exported_activity"
EXPORTED_SERVICE = "exported_service"
EXPORTED_RECEIVER = "exported_receiver"
EXPORTED_PROVIDER = "exported_provider"
MANIFEST = "manifest"
CODE = "code"
NETWORK = "network"
CERTIFICATE = "certificate"
SECRETS = "secrets"
STORAGE = "storage"


class Status(str, enum.Enum):
    """Every finding in the final report has exactly one of these statuses."""

    CONFIRMED = "Confirmed"  # A check ran and captured evidence proving it.
    UNCONFIRMED = "Unconfirmed"  # A check ran but could not prove it.
    NOT_TESTABLE = "Not testable"  # No check exists, or the check could not run.


class Severity(enum.IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3

    @property
    def label(self) -> str:
        return self.name.capitalize()

    @classmethod
    def from_mobsf(cls, value: object) -> Severity | None:
        """Map a MobSF severity string to ours.

        Returns None for non-issues ("secure", "good"), which are dropped.
        """
        mapping = {
            "critical": cls.HIGH,
            "high": cls.HIGH,
            "warning": cls.MEDIUM,
            "medium": cls.MEDIUM,
            "low": cls.LOW,
            "hotspot": cls.LOW,
            "info": cls.INFO,
        }
        return mapping.get(str(value or "").strip().lower())


@dataclass
class Finding:
    id: str
    title: str
    severity: Severity
    category: str
    description: str = ""
    component: str | None = None
    rule: str = ""
    references: list[str] = field(default_factory=list)
    source: str = "mobsf"
    status: Status = Status.NOT_TESTABLE
    status_reason: str = "No automated verification check exists for this finding yet."
    evidence: list[str] = field(default_factory=list)  # Paths relative to the run folder.
    check_id: str | None = None
    rank: int = 0
    explanation: str = ""  # Optional plain-language text from LLM triage.
    # Raw data checks need but that must never reach the report (e.g. secret values).
    private: dict = field(default_factory=dict, repr=False)

    def to_dict(self) -> dict:
        data = asdict(self)
        data.pop("private", None)
        data["severity"] = self.severity.label
        data["status"] = self.status.value
        return data


@dataclass
class CheckResult:
    status: Status
    reason: str
    evidence: list[str] = field(default_factory=list)
