"""
澳洲競爭與消費者委員會 (ACCC) / 國家反詐騙中心 (Scamwatch) 適配器
資料授權：Creative Commons Attribution 3.0 Australia (CC BY 3.0 AU)
涵蓋：冒名金融投資、跨國釣魚詐騙網域、未經許可外匯平台
"""
import json
import logging
import re
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, List, Set
from .base import BaseSourceAdapter, deterministic_uuid

ACCC_SCAMWATCH_API_ENDPOINT = "https://data.gov.au/data/api/3/action/datastore_search?resource_id=scamwatch-high-risk-domains"
PROJECT_EPOCH = "2026-01-01T00:00:00.000Z"

class ScamwatchAUAdapter(BaseSourceAdapter):
    SOURCE_ID = "au-accc-scamwatch"
    SOURCE_NAME = "Australian Competition and Consumer Commission (澳洲國家反詐騙中心)"
    LICENSE_TYPE = "CC BY 3.0 AU (data.gov.au)"
    IS_ACTIVE = True

    def _extract_domains(self, text: str | None) -> Set[str]:
        domains = set()
        if not text:
            return domains

        candidates = re.split(r'[\s,;\n\r\t]+', str(text).strip())
        for raw in candidates:
            if not raw or "." not in raw:
                continue
            target = raw if re.match(r'^https?://', raw, re.IGNORECASE) else f"http://{raw}"
            try:
                parsed = urllib.parse.urlparse(target)
                domain = (parsed.hostname or "").lower().strip(".,;:)'\"")
                if domain and not domain.endswith(".gov.au") and not domain.endswith(".accc.gov.au"):
                    domains.add(domain)
            except Exception:
                continue
        return domains

    def fetch_and_parse(self) -> List[Dict[str, Any]]:
        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "application/json"
        }
        req = urllib.request.Request(ACCC_SCAMWATCH_API_ENDPOINT, headers=headers)
        raw_payload = None

        max_retries = 2
        for attempt in range(1, max_retries + 1):
            try:
                logging.info("正在請求澳洲 Scamwatch API (嘗試 %d/%d)...", attempt, max_retries)
                with urllib.request.urlopen(req, timeout=30) as response:
                    if response.status == 200:
                        raw_payload = json.loads(response.read().decode("utf-8"))
                        break
            except Exception as e:
                logging.warning("Scamwatch API 嘗試 %d 失敗: %s", attempt, str(e))
                time.sleep(2)

        stix_objects = []
        # 1. 官方來源 Identity SDO
        accc_id = f"identity--{deterministic_uuid('AU_ACCC_SCAMWATCH_OFFICIAL')}"
        stix_objects.append({
            "type": "identity",
            "spec_version": "2.1",
            "id": accc_id,
            "created": PROJECT_EPOCH,
            "modified": PROJECT_EPOCH,
            "name": self.SOURCE_NAME,
            "identity_class": "government",
            "sectors": ["government"],
            "contact_information": "https://www.scamwatch.gov.au"
        })

        if not raw_payload:
            logging.warning("Scamwatch API 暫時連線逾時，跳過即時拉取。")
            return stix_objects

        records = raw_payload.get("result", {}).get("records", [])
        logging.info("澳洲 Scamwatch 取得原始記錄數: %d", len(records))

        for rec in records:
            domain_raw = str(rec.get("domain") or rec.get("url") or rec.get("target") or "").strip()
            date_str = str(rec.get("date_added") or rec.get("date") or "").strip()
            scam_type = str(rec.get("scam_type") or "Investment / Impersonation Scam").strip()

            if not domain_raw:
                continue

            if date_str:
                try:
                    clean_date = date_str[:10].replace("/", "-")
                    pub_time = datetime.strptime(clean_date, "%Y-%m-%d").replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
                except Exception:
                    pub_time = PROJECT_EPOCH
                    clean_date = "unknown-date"
            else:
                pub_time = PROJECT_EPOCH
                clean_date = "unknown-date"

            domains = self._extract_domains(domain_raw)
            indicator_ids = []

            for domain in domains:
                ind_id = f"indicator--{deterministic_uuid(f'domain:{domain}')}"
                indicator_ids.append(ind_id)
                stix_objects.append({
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": ind_id,
                    "created": pub_time,
                    "modified": pub_time,
                    "pattern_type": "stix",
                    "pattern": f"[domain-name:value = '{domain}']",
                    "valid_from": pub_time,
                    "confidence": 90
                })

            report_seed = f"AU_SCAMWATCH_{clean_date}_{domain_raw[:40]}"
            report_id = f"report--{deterministic_uuid(report_seed)}"

            stix_objects.append({
                "type": "report",
                "spec_version": "2.1",
                "id": report_id,
                "created": pub_time,
                "modified": pub_time,
                "name": f"Scamwatch Alert: {list(domains)[0] if domains else domain_raw}",
                "description": f"Verified fraudulent domain [{scam_type}] reported to Australian National Anti-Scam Centre.",
                "published": pub_time,
                "confidence": 90,
                "x_veritas_license": self.LICENSE_TYPE,
                "external_references": [{
                    "source_name": "ACCC Scamwatch",
                    "url": "https://www.scamwatch.gov.au"
                }],
                "object_refs": [accc_id] + indicator_ids
            })

        return stix_objects
