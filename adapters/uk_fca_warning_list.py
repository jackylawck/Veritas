"""
英國金融行為監管局 (FCA) 未經授權與冒名金融實體警示清單適配器
資料授權：UK Open Government Licence (OGL v3.0)
涵蓋：未經授權金融經紀商、冒名持牌公司 (Clone Firms)、跨國外匯詐騙網域
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

# 英國政府 / FCA 官方開放資料端點
UK_FCA_API_ENDPOINT = "https://www.fca.org.uk/api/v1/warning-list"
PROJECT_EPOCH = "2026-01-01T00:00:00.000Z"

class FCAWarningListAdapter(BaseSourceAdapter):
    SOURCE_ID = "uk-fca-warning-list"
    SOURCE_NAME = "Financial Conduct Authority (英國金融行為監管局)"
    LICENSE_TYPE = "Open Government Licence v3.0 (UK)"
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
                if domain and not domain.endswith(".gov.uk") and not domain.endswith(".fca.org.uk"):
                    domains.add(domain)
            except Exception:
                continue
        return domains

    def fetch_and_parse(self) -> List[Dict[str, Any]]:
        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "application/json"
        }
        req = urllib.request.Request(UK_FCA_API_ENDPOINT, headers=headers)
        raw_payload = None

        max_retries = 2
        for attempt in range(1, max_retries + 1):
            try:
                logging.info("正在請求英國 FCA API (嘗試 %d/%d)...", attempt, max_retries)
                with urllib.request.urlopen(req, timeout=30) as response:
                    if response.status == 200:
                        raw_payload = json.loads(response.read().decode("utf-8"))
                        break
            except Exception as e:
                logging.warning("英國 FCA API 嘗試 %d 失敗: %s", attempt, str(e))
                time.sleep(2)

        stix_objects = []
        # 1. 官方來源 Identity SDO
        fca_id = f"identity--{deterministic_uuid('UK_FCA_OFFICIAL')}"
        stix_objects.append({
            "type": "identity",
            "spec_version": "2.1",
            "id": fca_id,
            "created": PROJECT_EPOCH,
            "modified": PROJECT_EPOCH,
            "name": self.SOURCE_NAME,
            "identity_class": "government",
            "sectors": ["financial-services", "government"],
            "contact_information": "https://www.fca.org.uk"
        })

        if not raw_payload:
            logging.warning("FCA API 暫時連線逾時，跳過即時拉取。")
            return stix_objects

        items = raw_payload.get("data", raw_payload.get("items", []))
        logging.info("英國 FCA 取得原始警示記錄數: %d", len(items))

        for item in items:
            name = str(item.get("name") or item.get("firm_name") or "Unauthorised Firm").strip()
            date_str = str(item.get("date") or item.get("published_date") or "").strip()
            website_str = str(item.get("website") or item.get("url") or "")
            is_clone = bool(item.get("is_clone", False))

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

            # 2. 涉詐實體 Identity SDO
            entity_id = f"identity--{deterministic_uuid(f'UK_FCA_ENTITY_{name}')}"
            stix_objects.append({
                "type": "identity",
                "spec_version": "2.1",
                "id": entity_id,
                "created": pub_time,
                "modified": pub_time,
                "name": name,
                "identity_class": "organization",
                "sectors": ["financial-services"]
            })

            # 3. 提取惡意網域 IoC
            domains = self._extract_domains(website_str)
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

            # 4. 生成 Report SDO
            report_seed = f"UK_FCA_{clean_date}_{name}"
            report_id = f"report--{deterministic_uuid(report_seed)}"

            desc_label = "Unauthorised Clone Firm" if is_clone else "Unauthorised Financial Entity"
            stix_objects.append({
                "type": "report",
                "spec_version": "2.1",
                "id": report_id,
                "created": pub_time,
                "modified": pub_time,
                "name": f"FCA Warning: {name}",
                "description": f"{desc_label} flagged by the UK Financial Conduct Authority.",
                "published": pub_time,
                "confidence": 95,
                "x_veritas_license": self.LICENSE_TYPE,
                "external_references": [{
                    "source_name": "FCA Warning List",
                    "url": "https://www.fca.org.uk/consumers/warning-list-unauthorised-firms"
                }],
                "object_refs": [fca_id, entity_id] + indicator_ids
            })

        return stix_objects
