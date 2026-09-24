"""
美國聯邦調查局 (FBI) 網絡犯罪投訴中心 (IC3) 公共警示適配器
資料授權：U.S. Government Work / Public Domain
涵蓋：跨國 BEC 詐騙、CEO/CFO Deepfake 冒名、重大金融詐騙網域
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

FBI_IC3_API_ENDPOINT = "https://www.ic3.gov/api/v1/public-alerts.json"
PROJECT_EPOCH = "2026-01-01T00:00:00.000Z"

class FBIIC3AlertAdapter(BaseSourceAdapter):
    SOURCE_ID = "us-fbi-ic3-alerts"
    SOURCE_NAME = "Federal Bureau of Investigation IC3 (美國聯邦調查局網絡犯罪投訴中心)"
    LICENSE_TYPE = "U.S. Public Domain"
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
                if domain and not domain.endswith(".gov") and not domain.endswith(".ic3.gov"):
                    domains.add(domain)
            except Exception:
                continue
        return domains

    def fetch_and_parse(self) -> List[Dict[str, Any]]:
        headers = {
            "User-Agent": "Veritas-OSINT-Mirror/1.0 (+https://github.com/jackylawck/Veritas)",
            "Accept": "application/json"
        }
        req = urllib.request.Request(FBI_IC3_API_ENDPOINT, headers=headers)
        raw_payload = None

        max_retries = 2
        for attempt in range(1, max_retries + 1):
            try:
                logging.info("正在請求 FBI IC3 API (嘗試 %d/%d)...", attempt, max_retries)
                with urllib.request.urlopen(req, timeout=30) as response:
                    if response.status == 200:
                        raw_payload = json.loads(response.read().decode("utf-8"))
                        break
            except Exception as e:
                logging.warning("FBI IC3 API 嘗試 %d 失敗: %s", attempt, str(e))
                time.sleep(2)

        stix_objects = []
        # 1. 官方來源 Identity SDO
        fbi_id = f"identity--{deterministic_uuid('US_FBI_IC3_OFFICIAL')}"
        stix_objects.append({
            "type": "identity",
            "spec_version": "2.1",
            "id": fbi_id,
            "created": PROJECT_EPOCH,
            "modified": PROJECT_EPOCH,
            "name": self.SOURCE_NAME,
            "identity_class": "government",
            "sectors": ["government"],
            "contact_information": "https://www.ic3.gov"
        })

        if not raw_payload:
            logging.warning("FBI IC3 API 暫時連線逾時，跳過即時拉取。")
            return stix_objects

        items = raw_payload if isinstance(raw_payload, list) else raw_payload.get("alerts", raw_payload.get("data", []))
        logging.info("FBI IC3 取得原始記錄數: %d", len(items))

        for item in items:
            title = str(item.get("title") or "FBI IC3 Public Service Announcement").strip()
            date_str = str(item.get("date") or item.get("publish_date") or "").strip()
            details = str(item.get("summary") or item.get("text") or "")
            link = str(item.get("url") or item.get("link") or "").strip()

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

            domains = self._extract_domains(details)
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
                    "confidence": 95
                })

            report_seed = f"FBI_IC3_{clean_date}_{title[:40]}"
            report_id = f"report--{deterministic_uuid(report_seed)}"

            stix_objects.append({
                "type": "report",
                "spec_version": "2.1",
                "id": report_id,
                "created": pub_time,
                "modified": pub_time,
                "name": f"FBI PSA: {title}",
                "description": details[:300] if details else "High-priority alert issued by FBI IC3.",
                "published": pub_time,
                "confidence": 95,
                "x_veritas_license": self.LICENSE_TYPE,
                "external_references": [{
                    "source_name": "FBI IC3",
                    "url": link or "https://www.ic3.gov"
                }],
                "object_refs": [fbi_id] + indicator_ids
            })

        return stix_objects
