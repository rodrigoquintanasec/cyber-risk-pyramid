import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.connectors import epss, kev, nvd  # noqa: E402
from app.correlation import correlate_cpes, correlate_kev, kev_is_ambiguous_candidate, parse_cpe  # noqa: E402
from app.config import ScoringConfig
from app.scoring import CveSignal, cve_weight, evidence_class, level_for, score_technology  # noqa: E402

NOW = datetime(2026, 11, 16, tzinfo=timezone.utc)


def iso(days):
    return (NOW - timedelta(days=days)).isoformat()


# ---- correlation
def test_parse_cpe():
    assert parse_cpe("cpe:2.3:o:microsoft:windows_server_2022:-:*:*:*:*:*:*:*") == ("o", "microsoft", "windows_server_2022")
    assert parse_cpe("garbage") is None
    assert parse_cpe("cpe:2.3:a:*:*:*") is None


def test_windows_server_only_not_all_microsoft():
    assert "windows-server" in correlate_cpes(["o:microsoft:windows_server_2019"])
    assert set(correlate_cpes(["o:microsoft:windows_10_1809"])) == {"windows-10"}      # its own catalogue entry, never Windows Server
    assert correlate_cpes(["o:microsoft:windows_xp", "a:microsoft:paint"]) == {}                      # same vendor, unlisted products: no correlation
    assert correlate_cpes(["a:microsoft:edge"]) == {}


def test_fortinet_only_catalog_products():
    assert "fortinet" in correlate_cpes(["o:fortinet:fortios"])
    assert correlate_cpes(["a:fortinet:forticlient"]) == {}


def test_kev_matching_and_ambiguity():
    assert correlate_kev("Fortinet", "FortiOS and FortiProxy").id == "fortinet"
    assert correlate_kev("Microsoft", "Windows") is None  # generic: needs NVD CPE confirmation
    assert correlate_kev("Microsoft", "Windows Server Update Service (WSUS)").id == "windows-server"
    assert correlate_kev("VMware", "ESXi").id == "vmware"
    assert correlate_kev("Linux", "Kernel").id == "linux"
    assert correlate_kev("Acme", "Widget") is None
    assert kev_is_ambiguous_candidate("Microsoft") and not kev_is_ambiguous_candidate("Acme")


def test_multi_tech_cve_has_no_duplicates_per_tech():
    r = correlate_cpes(["o:vmware:esxi", "a:vmware:vcenter_server", "o:linux:linux_kernel"])
    assert set(r) == {"vmware", "linux"}


# ---- scoring
def kev_sig(i, days_added, cvss=9.8, epss=0.9, ransom=False):
    return CveSignal(f"CVE-2026-{i:04d}", iso(days_added + 5), cvss, epss, True, iso(days_added)[:10], ransom)


def low_sig(i, cvss=3.1, epss=0.001, days=20):
    return CveSignal(f"CVE-2025-{i:05d}", iso(days), cvss, epss, False)


def test_kev_scores_higher_than_plain_cvss():
    plain = CveSignal("CVE-2026-0001", iso(10), 9.8, 0.01, False)
    assert cve_weight(kev_sig(2, 5), NOW) > cve_weight(plain, NOW)


def test_single_exploited_vulnerability_outweighs_hundreds_of_low_relevance():
    one = score_technology([kev_sig(1, 3, ransom=True)], NOW)["score"]
    many = score_technology([low_sig(i) for i in range(500)], NOW)["score"]
    mid = score_technology([low_sig(i, cvss=6.5, epss=0.02) for i in range(500)], NOW)["score"]
    assert one >= 75 and many < 25 and mid < 25
    assert one > 3 * many


def test_volume_never_raises_score_beyond_corroboration_bound():
    cfg = ScoringConfig()
    base = [low_sig(0, cvss=7.0, epss=0.05)]
    s1 = score_technology(base, NOW)["score"]
    s500 = score_technology(base + [low_sig(i, cvss=7.0, epss=0.05) for i in range(1, 500)], NOW)["score"]
    peak = s1 / 100
    assert s500 >= s1  # more CVEs never lower the score
    assert s500 - s1 <= 100 * cfg.corroboration * (1 - peak) + 0.2
    assert level_for(s500)[0] == level_for(s1)[0] or s500 - s1 < 8


def test_adding_irrelevant_cves_does_not_change_top_driven_score_much():
    base = [kev_sig(1, 10)]
    s1 = score_technology(base, NOW)["score"]
    s2 = score_technology(base + [low_sig(i) for i in range(300)], NOW)["score"]
    assert 0 <= s2 - s1 < 3


def test_recent_exploitation_distinguished_from_known_kev():
    recent, old = kev_sig(1, 5), kev_sig(2, 400)
    assert evidence_class(recent, NOW) == "recent_exploitation"
    assert evidence_class(old, NOW) == "known_exploited"
    assert evidence_class(low_sig(3), NOW) == "none"
    assert cve_weight(recent, NOW) > cve_weight(old, NOW)


def test_old_exploited_fades_but_is_not_discarded():
    old = kev_sig(1, 1000, cvss=9.8, epss=0.9)
    w = cve_weight(old, NOW)
    cfg = ScoringConfig()
    assert w > cfg.w_epss * 0.99 + cfg.w_kev * cfg.kev_floor * 0.99  # floor keeps KEV relevance
    assert w < cve_weight(kev_sig(2, 3), NOW)
    assert 40 < score_technology([old], NOW)["score"] < 75  # relevant but no longer dominant


def test_old_unexploited_cve_decays():
    new = CveSignal("CVE-2026-0003", iso(1), 8.0, 0.1, False)
    old = CveSignal("CVE-2026-0004", iso(300), 8.0, 0.1, False)
    assert cve_weight(new, NOW) > cve_weight(old, NOW)


def test_no_signals_is_insufficient_not_zero():
    assert score_technology([], NOW)["score"] is None


def test_score_bounds_and_missing_cvss():
    sigs = [CveSignal(f"CVE-2026-{i:04d}", iso(2), None, None, True, iso(2)[:10], True) for i in range(500)]
    assert 0 <= score_technology(sigs, NOW)["score"] <= 100


def test_levels_boundaries():
    assert level_for(0)[0] == "low" and level_for(24.9)[0] == "low"
    assert level_for(25)[0] == "medium" and level_for(49.9)[0] == "medium"
    assert level_for(50)[0] == "high" and level_for(74.9)[0] == "high"
    assert level_for(75)[0] == "critical" and level_for(100)[0] == "critical"
    assert level_for(None)[0] == "unknown"


# ---- connector validation
def test_kev_parse_skips_invalid():
    out = kev.parse({"vulnerabilities": [
        {"cveID": "CVE-2024-1234", "vendorProject": "V", "product": "P", "dateAdded": "2024-01-01", "knownRansomwareCampaignUse": "Known"},
        {"cveID": "bad"}, "x"]})
    assert len(out) == 1 and out[0]["ransomware"] == 1


def test_nvd_parse_item():
    item = {"cve": {"id": "CVE-2026-1111", "published": "2026-10-01T00:00:00.000", "descriptions": [{"lang": "en", "value": "d"}],
                    "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": 9.8}}]},
                    "configurations": [{"nodes": [{"cpeMatch": [
                        {"vulnerable": True, "criteria": "cpe:2.3:o:vmware:esxi:7.0:*:*:*:*:*:*:*"},
                        {"vulnerable": False, "criteria": "cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*"}]}]}]}}
    r = nvd.parse_item(item)
    assert r["cvss"] == 9.8 and r["cpes"] == "o:vmware:esxi"
    assert nvd.parse_item({"cve": {"id": "CVE-2026-2222", "vulnStatus": "Rejected"}}) is None


def test_epss_parse():
    assert epss.parse({"data": [{"cve": "CVE-1", "epss": "0.5", "percentile": "0.9", "date": "d"}, {"cve": "x", "epss": "9"}]})[0]["score"] == 0.5
