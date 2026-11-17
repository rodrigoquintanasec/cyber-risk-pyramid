"""Deterministic scoring of the *current threat state* of a technology. Pure functions, no I/O.
Formula: see ScoringConfig in config.py. The score reflects published threat signals, NOT the
real risk of any organisation."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from .config import ScoringConfig, scoring_config

LEVELS = (  # (min score, key, label, color)
    (75, "critical", "Critical", "#EF4444"),
    (50, "high", "High", "#F97316"),
    (25, "medium", "Medium", "#EAB308"),
    (0, "low", "Low", "#22C55E"),
)
UNKNOWN = ("unknown", "Insufficient data", "#64748B")


@dataclass
class CveSignal:
    cve_id: str
    published: str | None
    cvss: float | None
    epss: float | None
    kev: bool
    kev_date_added: str | None = None
    ransomware: bool = False


def level_for(score: float | None) -> tuple[str, str, str]:
    if score is None:
        return UNKNOWN
    for min_score, key, label, color in LEVELS:
        if score >= min_score:
            return key, label, color
    return LEVELS[-1][1:]


def _parse(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        d = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def _days(ts: str | None, now: datetime) -> float | None:
    d = _parse(ts)
    return max(0.0, (now - d).total_seconds() / 86400) if d else None


def evidence_class(s: CveSignal, now: datetime, cfg: ScoringConfig = scoring_config) -> str:
    """'recent_exploitation' (KEV addition within recent_days) | 'known_exploited' (older KEV) | 'none'."""
    if not s.kev:
        return "none"
    age = _days(s.kev_date_added, now)
    return "recent_exploitation" if age is not None and age <= cfg.recent_days else "known_exploited"


def cve_breakdown(s: CveSignal, now: datetime, cfg: ScoringConfig = scoring_config) -> dict:
    pub_age = _days(s.published, now)
    if pub_age is None:
        pub_age = _days(s.kev_date_added, now)  # proxy when NVD data is missing
    if pub_age is None:
        pub_age = 365.0
    cvss_n = (s.cvss / 10.0) if s.cvss is not None else cfg.cvss_missing
    decay_pub = max(cfg.cvss_floor, 0.5 ** (pub_age / cfg.cvss_half_life_days))
    parts = {
        "cvss": cfg.w_cvss * cvss_n * decay_pub,
        "epss": cfg.w_epss * (min(1.0, (s.epss or 0.0) / cfg.epss_cap) if cfg.epss_cap > 0 else 0.0),
        "kev": 0.0, "recent": 0.0, "ransomware": 0.0,
    }
    kev_age = _days(s.kev_date_added, now) if s.kev else None
    if s.kev:
        ka = 365.0 if kev_age is None else kev_age
        decay_kev = max(cfg.kev_floor, 0.5 ** (ka / cfg.kev_half_life_days))
        parts["kev"] = cfg.w_kev * decay_kev
        parts["recent"] = cfg.w_recent * 0.5 ** (ka / cfg.recent_half_life_days)
        parts["ransomware"] = cfg.w_ransom * decay_kev if s.ransomware else 0.0
    weight = max(0.0, min(1.0, sum(parts.values())))
    return {"weight": weight, "parts": parts, "evidence": evidence_class(s, now, cfg), "kev_age_days": kev_age}


def cve_weight(s: CveSignal, now: datetime, cfg: ScoringConfig = scoring_config) -> float:
    return cve_breakdown(s, now, cfg)["weight"]


def score_technology(signals: list[CveSignal], now: datetime | None = None, cfg: ScoringConfig = scoring_config) -> dict:
    """Returns {'score': float|None, 'components', 'weights', 'breakdowns'}; score None = no correlated signals."""
    now = now or datetime.now(timezone.utc)
    if not signals:
        return {"score": None, "components": {}, "weights": {}, "breakdowns": {}}
    bd = {s.cve_id: cve_breakdown(s, now, cfg) for s in signals}
    ws = sorted((b["weight"] for b in bd.values()), reverse=True)
    peak = ws[0]
    rest = ws[1 : 1 + cfg.corroboration_n]
    corr = sum(rest) / cfg.corroboration_n if cfg.corroboration_n > 0 else 0.0
    score = 100 * min(1.0, peak + cfg.corroboration * (1 - peak) * corr)
    return {
        "score": round(max(0.0, score), 1),
        "components": {
            "peak": {"value": round(peak, 3), "points": round(100 * peak, 1)},
            "corroboration": {"value": round(corr, 3), "points": round(100 * cfg.corroboration * (1 - peak) * corr, 1)},
        },
        "weights": {k: b["weight"] for k, b in bd.items()},
        "breakdowns": bd,
    }
