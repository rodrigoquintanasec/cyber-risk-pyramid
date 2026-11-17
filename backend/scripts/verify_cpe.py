"""Verify the CPE ids of the seed catalogue against the official NVD CPE dictionary (public API, rate limited: ~1 request / 6.5 s).
Usage: python scripts/verify_cpe.py OUT.json   -> {"o:vendor:product": total_results | -1 (error)}"""
import json
import sys
import time
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app.catalog_seed import NEW  # noqa: E402

out_path = Path(sys.argv[1])
res = json.loads(out_path.read_text()) if out_path.exists() else {}
tokens = sorted({t for row in NEW for t in row[8].split()})
with httpx.Client(timeout=40, headers={"User-Agent": "cyber-risk-pyramid-catalog-check"}) as c:
    for t in tokens:
        if t in res and res[t] >= 0:
            continue
        part, v, p = t.split(":", 2)[0], t.split(":")[1], t.split(":", 2)[2]
        for attempt in range(4):
            try:
                r = c.get("https://services.nvd.nist.gov/rest/json/cpes/2.0", params={"cpeMatchString": f"cpe:2.3:{part}:{v}:{p}", "resultsPerPage": 1})
                if r.status_code == 200:
                    res[t] = r.json().get("totalResults", 0); break
                time.sleep(35)
            except Exception:
                time.sleep(15)
        else:
            res[t] = -1
        out_path.write_text(json.dumps(res, indent=1))
        time.sleep(6.5)
print("done", sum(1 for v in res.values() if v > 0), "ok of", len(tokens))
