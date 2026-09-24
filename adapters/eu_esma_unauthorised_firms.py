"""
歐洲證券及市場管理局 (ESMA) 全歐未經授權機構與冒名實體清單適配器
資料授權：EU Legal Notice (European Union Open Data)
涵蓋：歐盟全境 (27國) 協調查處之偽冒持牌經紀商、未受管制的跨國虛擬資產交易平台
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

ESMA_UNAUTHORISED_API_ENDPOINT = "https://www.esma.europa.eu/api/v1/registers/unauthorised-firms.json"
PROJECT_EPOCH = "2026-01-01T00:00:00.000Z"

class ESMAUnauthorisedAdapter(BaseSourceAdapter):
    SOURCE_ID = "eu-esma-unauthorised-firms"
    SOURCE_NAME = "European Securities and Markets Authority (歐洲證券及市場管理局)"
    LICENSE_TYPE = "EU Open Data Legal Notice"
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
                if domain and not domain.endswith(".europa.eu") and not domain.endswith(".esma.europa.eu"):
                    domains.add(domain)
            except Exception:
                continue
        return domains

    def fetch_and_parse(self) -> List[Dict[str, Any]]:
        headers = {
            "User-Agent": "Veritas-OSINT-Mirror/1.0 (+https://github.com/jackylawck/Veritas)",
            "Accept": "application/json"
        }
        stix_objects = []

        # 1. 官方來源 Identity SDO
        esma_id = f"identity--{deterministic_uuid('EU_ESMA_OFFICIAL')}"
        stix_objects.append({
            "type": "identity",
            "spec_version": "2.1",
            "id": esma_id,
            "created": PROJECT_EPOCH,
            "modified": PROJECT_EPOCH,
            "name": self.SOURCE_NAME,
            "identity_class": "government",
            "sectors": ["financial-services", "government"],
            "contact_information": "https://www.esma.europa.eu"
        })

        raw_payload = None
        max_retries = 2
        req = urllib.request.Request(ESMA_UNAUTHORISED_API_ENDPOINT, headers=headers)
        for attempt in range(1, max_retries + 1):
            try:
                logging.info("正在請求歐盟 ESMA API (嘗試 %d/%d)...", attempt, max_retries)
                with urllib.request.urlopen(req, timeout=30) as response:
                    if response.status == 200:
                        raw_payload = json.loads(response.read().decode("utf-8"))
                        break
            except Exception as e:
                logging.warning("歐盟 ESMA API 嘗試 %d 失敗: %s", attempt, str(e))
                time.sleep(2)

        if not raw_payload:
            logging.warning("ESMA API 暫時連線逾時，跳過即時拉取。")
            return stix_objects

        items = raw_payload if isinstance(raw_payload, list) else raw_payload.get("items", raw_payload.get("data", []))
        logging.info("歐盟 ESMA 取得原始警示記錄數: %d", len(items))

        for item in items:
            firm_name = str(item.get("firm_name") or item.get("name") or "Unauthorised Entity").strip()
            date_str = str(item.get("warning_date") or item.get("date") or "").strip()
            website_str = str(item.get("website") or item.get("url") or "")
            origin_authority = str(item.get("national_authority") or "EU Member State NCA").strip()

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
            entity_id = f"identity--{deterministic_uuid(f'EU_ESMA_ENTITY_{firm_name}')}"
            stix_objects.append({
                "type": "identity",
                "spec_version": "2.1",
                "id": entity_id,
                "created": pub_time,
                "modified": pub_time,
                "name": firm_name,
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
            report_seed = f"EU_ESMA_{clean_date}_{firm_name}"
            report_id = f"report--{deterministic_uuid(report_seed)}"

            stix_objects.append({
                "type": "report",
                "spec_version": "2.1",
                "id": report_id,
                "created": pub_time,
                "modified": pub_time,
                "name": f"ESMA Unauthorised Warning: {firm_name}",
                "description": f"Entity flagged as operating without proper authorization by {origin_authority} via ESMA register.",
                "published": pub_time,
                "confidence": 95,
                "x_veritas_license": self.LICENSE_TYPE,
                "external_references": [{
                    "source_name": "ESMA Non-authorisation Register",
                    "url": "https://www.esma.europa.eu/investor-corner/warning-and-publications-for-investors"
                }],
                "object_refs": [esma_id, entity_id] + indicator_ids
            })

        return stix_objects
