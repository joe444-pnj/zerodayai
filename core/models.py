"""
core/models.py — SQLAlchemy ORM Models

Defines the database schema for scans, findings, and tasks.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Optional

from sqlalchemy import (
    Column, DateTime, Float, ForeignKey, Integer, String, Text, Enum as SAEnum
)
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    pass


# ─── Enumerations ───────────────────────────────────────────────────

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


class ScanStatus(str, Enum):
    PENDING   = "pending"
    RUNNING   = "running"
    PAUSED    = "paused"
    COMPLETED = "completed"
    FAILED    = "failed"


class AgentType(str, Enum):
    STATIC  = "static"
    LLM     = "llm"
    FUZZER  = "fuzzer"
    NETWORK = "network"


class FindingCategory(str, Enum):
    # Injection
    SQL_INJECTION        = "sql_injection"
    COMMAND_INJECTION    = "command_injection"
    LDAP_INJECTION       = "ldap_injection"
    XPATH_INJECTION      = "xpath_injection"

    # Web
    XSS                  = "xss"
    SSRF                 = "ssrf"
    CSRF                 = "csrf"
    OPEN_REDIRECT        = "open_redirect"
    SSTI                 = "ssti"
    XXE                  = "xxe"
    PATH_TRAVERSAL       = "path_traversal"

    # Auth
    AUTH_BYPASS          = "auth_bypass"
    BROKEN_ACCESS        = "broken_access"
    INSECURE_JWT         = "insecure_jwt"
    OAUTH_FLAW           = "oauth_flaw"
    SESSION_FIXATION     = "session_fixation"

    # Deserialization
    DESERIALIZATION      = "deserialization"

    # Memory Safety
    BUFFER_OVERFLOW      = "buffer_overflow"
    USE_AFTER_FREE       = "use_after_free"
    INTEGER_OVERFLOW     = "integer_overflow"
    FORMAT_STRING        = "format_string"
    NULL_DEREFERENCE     = "null_dereference"

    # Logic
    RACE_CONDITION       = "race_condition"
    LOGIC_FLAW           = "logic_flaw"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    TOCTOU               = "toctou"

    # Crypto
    WEAK_CRYPTO          = "weak_crypto"
    HARDCODED_CREDS      = "hardcoded_creds"
    SENSITIVE_EXPOSURE   = "sensitive_exposure"

    # Supply Chain
    VULNERABLE_DEP       = "vulnerable_dep"
    TYPOSQUATTING        = "typosquatting"

    # Network
    OPEN_PORT            = "open_port"
    EXPOSED_SERVICE      = "exposed_service"
    MISCONFIGURATION     = "misconfiguration"

    # Other
    OTHER                = "other"


# ─── ORM Models ─────────────────────────────────────────────────────

class Scan(Base):
    """Represents a single scan session."""
    __tablename__ = "scans"

    id       = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    target   = Column(String(512), nullable=False)
    label    = Column(String(256), nullable=True)
    status   = Column(SAEnum(ScanStatus), default=ScanStatus.PENDING, nullable=False)
    created_at  = Column(DateTime, default=datetime.utcnow, nullable=False)
    started_at  = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)
    config_snapshot = Column(Text, nullable=True)  # JSON string of scan config
    notes    = Column(Text, nullable=True)

    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    tasks    = relationship("AgentTask", back_populates="scan", cascade="all, delete-orphan")

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    def __repr__(self):
        return f"<Scan id={self.id[:8]} target={self.target} status={self.status}>"


class Finding(Base):
    """A single discovered vulnerability or security issue."""
    __tablename__ = "findings"

    id             = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id        = Column(String(36), ForeignKey("scans.id"), nullable=False)
    agent          = Column(SAEnum(AgentType), nullable=False)
    category       = Column(SAEnum(FindingCategory), default=FindingCategory.OTHER)
    severity       = Column(SAEnum(Severity), default=Severity.INFO, nullable=False)
    title          = Column(String(512), nullable=False)
    description    = Column(Text, nullable=False)
    file_path      = Column(String(512), nullable=True)
    line_number    = Column(Integer, nullable=True)
    code_snippet   = Column(Text, nullable=True)
    url            = Column(String(2048), nullable=True)
    parameter      = Column(String(256), nullable=True)
    payload        = Column(Text, nullable=True)
    poc            = Column(Text, nullable=True)      # Proof-of-concept exploit
    remediation    = Column(Text, nullable=True)
    cve_ids        = Column(Text, nullable=True)      # Comma-separated CVE IDs
    cvss_score     = Column(Float, nullable=True)
    references     = Column(Text, nullable=True)      # JSON list of URLs
    confidence     = Column(Float, default=0.8)       # 0.0–1.0
    false_positive = Column(Integer, default=0)       # 0 or 1 (bool-like)
    created_at     = Column(DateTime, default=datetime.utcnow, nullable=False)
    raw_output     = Column(Text, nullable=True)      # Raw tool output

    scan = relationship("Scan", back_populates="findings")

    def severity_emoji(self) -> str:
        return {
            Severity.CRITICAL: "🔴",
            Severity.HIGH:     "🟠",
            Severity.MEDIUM:   "🟡",
            Severity.LOW:      "🟢",
            Severity.INFO:     "🔵",
        }.get(self.severity, "⚪")

    def __repr__(self):
        return f"<Finding [{self.severity.upper()}] {self.title[:50]}>"


class AgentTask(Base):
    """Tracks individual agent execution tasks within a scan."""
    __tablename__ = "agent_tasks"

    id         = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id    = Column(String(36), ForeignKey("scans.id"), nullable=False)
    agent      = Column(SAEnum(AgentType), nullable=False)
    status     = Column(SAEnum(ScanStatus), default=ScanStatus.PENDING)
    sub_target = Column(String(512), nullable=True)  # File / URL / IP being processed
    started_at  = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)
    findings_count = Column(Integer, default=0)
    error_msg   = Column(Text, nullable=True)

    scan = relationship("Scan", back_populates="tasks")

    def __repr__(self):
        return f"<AgentTask agent={self.agent} status={self.status}>"


class AgentLearning(Base):
    """Semantic memory of past findings, false positives, and successes."""
    __tablename__ = "agent_learnings"

    id                 = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    pattern_context    = Column(Text, nullable=False)   # Vulnerable snippet, payload, or URL
    outcome_notes      = Column(Text, nullable=True)    # Working PoC, context, etc.
    is_false_positive  = Column(Integer, default=0)     # 0 or 1
    created_at         = Column(DateTime, default=datetime.utcnow, nullable=False)

    def __repr__(self):
        fp_str = "FP" if self.is_false_positive else "TRUE"
        return f"<AgentLearning [{fp_str}] id={self.id[:8]}>"
