"""Fake enterprise estate used by the resource servers."""

SYSTEMS = {
    "payments-api": {
        "name": "Payments API", "owner": "payments-team", "tier": "tier-1", "env": "prod",
        "criticality": "mission-critical", "data_classification": "PCI",
        "keywords": ["payment", "payments", "checkout", "card", "fraud", "transaction", "customers"],
        "status": "degraded", "version": "4.12.3", "region": "us-east-1",
        "vendor": {"partner": "partner.example", "service": "fraud-scoring", "api": "https://partner-api:8443"},
        "metrics": {"cpu_pct": 71, "mem_pct": 64, "p99_latency_ms": 1840, "error_rate_pct": 4.2, "rps": 1250},
        "diagnostics": [
            {"check": "upstream:fraud-scoring", "result": "timeout rate 11% (threshold 2%)", "severity": "high"},
            {"check": "db-pool", "result": "connection pool saturated 92%", "severity": "medium"},
            {"check": "tls-certs", "result": "valid, 61 days remaining", "severity": "ok"},
        ],
    },
    "erp-db": {
        "name": "ERP Database", "owner": "data-platform", "tier": "tier-1", "env": "prod",
        "criticality": "business-critical", "data_classification": "confidential",
        "keywords": ["erp", "invoice", "invoices", "finance", "ledger", "database", "vacuum", "backup"],
        "status": "healthy", "version": "PostgreSQL 16.4", "region": "us-east-1",
        "vendor": {"partner": "partner.example", "service": "backup-vault", "api": "https://partner-api:8443"},
        "metrics": {"cpu_pct": 38, "mem_pct": 71, "p99_latency_ms": 22, "error_rate_pct": 0.0, "rps": 640},
        "diagnostics": [
            {"check": "replication-lag", "result": "0.4s", "severity": "ok"},
            {"check": "vacuum", "result": "table invoices bloat 34%", "severity": "low"},
            {"check": "backups", "result": "last full backup 6h ago", "severity": "ok"},
        ],
    },
    "hr-portal": {
        "name": "HR Portal", "owner": "people-tech", "tier": "tier-2", "env": "prod",
        "criticality": "important", "data_classification": "PII",
        "keywords": ["hr", "payroll", "employee", "employees", "people", "benefits", "cve", "log4j"],
        "status": "healthy", "version": "2.3.0", "region": "eu-west-1",
        "vendor": {"partner": "partner.example", "service": "payroll-gateway", "api": "https://partner-api:8443"},
        "metrics": {"cpu_pct": 12, "mem_pct": 33, "p99_latency_ms": 310, "error_rate_pct": 0.3, "rps": 40},
        "diagnostics": [
            {"check": "dependency-scan", "result": "1 critical CVE in log4j-core 2.14.1", "severity": "critical"},
            {"check": "sso", "result": "OIDC metadata reachable", "severity": "ok"},
        ],
    },
}

RUNBOOKS = {
    "payments-api": "1) Check fraud-scoring upstream health. 2) Enable circuit breaker FRAUD_CB. "
                    "3) Scale db pool to 200. 4) Page payments on-call if error rate > 5%.",
    "erp-db": "1) Run VACUUM (ANALYZE) on bloated tables in maintenance window. 2) Verify replicas.",
    "hr-portal": "1) Patch vulnerable dependency. 2) Redeploy via pipeline hr-portal-prod. 3) Notify security.",
}

TICKETS = [
    {"id": "INC-1041", "system": "payments-api", "title": "Intermittent 504s from fraud-scoring", "state": "open"},
    {"id": "INC-1038", "system": "erp-db", "title": "Nightly vacuum overran window", "state": "resolved"},
]


# Targets that need the user's explicit approval before an agent may act on them.
APPROVAL_CLASSIFICATIONS = {"PCI"}
APPROVAL_CRITICALITY = {"mission-critical"}


def needs_approval(system: dict) -> bool:
    return system["data_classification"] in APPROVAL_CLASSIFICATIONS or system["criticality"] in APPROVAL_CRITICALITY
