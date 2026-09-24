"""
台灣內政部警政署 165 全民防騙網 - 涉詐與釣魚網址清單適配器
資料授權：政府資料開放授權條款 (data.gov.tw)
涵蓋：AI 換臉偽冒投資、簡訊詐騙 (Smishing)、冒名虛擬貨幣釣魚網站
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

# 台灣政府開放資料平台 165 涉詐網址公開端點
NPA_165_API_ENDPOINT = "https://data.gov.tw/api/v2/rest/datastore/A01010000C-001275-001"
PROJECT_EPOCH = "2026-01-01T00:00:00.000Z"

class NPA165ScamAdapter(BaseSourceAdapter):
    SOURCE_ID = "tw-npa-165-fraud-urls"
    SOURCE_NAME = "Taiwan National Police Agency 165 Anti-Fraud (台灣警政署165全民防騙)"
    LICENSE_TYPE = "Open Government Data License (data.gov.tw)"
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
                if domain and not domain.endswith(".gov.tw") and domain != "gov.tw":
                    domains.add(domain)
            except Exception:
                continue
        return domains

    def fetch_and_parse(self) -> List[Dict[str, Any]]:
        headers = {
            "User-Agent": "Veritas-OSINT-Mirror/1.0 (+https://github.com/jackylawck/Veritas)",
            "Accept": "application/json"
        }
        req = urllib.request.Request(NPA_165_API_ENDPOINT, headers=headers)
        raw_payload = None

        max_retries = 2
        for attempt in range(1, max_retries + 1):
            try:
                logging.info("正在請求台灣 165 API (嘗試 %d/%d)...", attempt, max_retries)
                with urllib.request.urlopen(req, timeout=30) as response:
                    if response.status == 200:
                        raw_payload = json.loads(response.read().decode("utf-8"))
                        break
            except Exception as e:
                logging.warning("台灣 165 API 嘗試 %d 失敗: %s", attempt, str(e))
                time.sleep(2)

        stix_objects = []
        # 1. 官方來源 Identity SDO
        npa_id = f"identity--{deterministic_uuid('NPA_165_OFFICIAL')}"
        stix_objects.append({
            "type": "identity",
            "spec_version": "2.1",
            "id": npa_id,
            "created": PROJECT_EPOCH,
            "modified": PROJECT_EPOCH,
            "name": self.SOURCE_NAME,
            "identity_class": "government",
            "sectors": ["government"],
            "contact_information": "https://165.npa.gov.tw"
        })

        if not raw_payload:
            logging.warning("165 API 暫時連線逾時，跳過即時拉取。")
            return stix_objects

        records = raw_payload.get("result", {}).get("records", [])
        if not records and isinstance(raw_payload, list):
            records = raw_payload

        logging.info("台灣 165 取得原始涉詐記錄數: %d", len(records))

        for item in records:
            # 欄位通常包含 網址 (weburl/url) 與 發布時間
            url_str = str(item.get("WEBURL") or item.get("url") or item.get("網址") or "").strip()
            date_str = str(item.get("CREATETIME") or item.get("date") or "").strip()

            if not url_str:
                continue

            if date_str:
                try:
                    # 支援 YYYY-MM-DD 或 YYYY/MM/DD
                    clean_date = date_str[:10].replace("/", "-")
                    pub_time = datetime.strptime(clean_date, "%Y-%m-%d").replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
                except Exception:
                    pub_time = PROJECT_EPOCH
                    clean_date = "unknown-date"
            else:
                pub_time = PROJECT_EPOCH
                clean_date = "unknown-date"

            domains = self._extract_domains(url_str)
            if not domains:
                continue

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

            report_seed = f"TW_165_{clean_date}_{url_str[:50]}"
            report_id = f"report--{deterministic_uuid(report_seed)}"

            stix_objects.append({
                "type": "report",
                "spec_version": "2.1",
                "id": report_id,
                "created": pub_time,
                "modified": pub_time,
                "name": f"165 Scam Alert: {list(domains)[0]}",
                "description": "High-risk fraudulent domain verified by Taiwan National Police Agency 165.",
                "published": pub_time,
                "confidence": 90,
                "x_veritas_license": self.LICENSE_TYPE,
                "external_references": [{
                    "source_name": "165 Anti-Fraud Database",
                    "url": "https://165.npa.gov.tw"
                }],
                "object_refs": [npa_id] + indicator_ids
            })

        return stix_objects
