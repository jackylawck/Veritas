"""
瑞士金融市場監督管理局 (FINMA) 警告名單 (Warning List) 適配器
資料授權：Swiss Federal Law on Freedom of Information / FINMA Public Terms
涵蓋：偽冒瑞士私人銀行、未經許可外匯/加密資產平台、非法吸金實體
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

FINMA_API_ENDPOINT = "https://www.finma.ch/api/v1/warning-list.json"
PROJECT_EPOCH = "2026-01-01T00:00:00.000Z"

class FINMAWarningAdapter(BaseSourceAdapter):
    SOURCE_ID = "ch-finma-warning-list"
    SOURCE_NAME = "Swiss Financial Market Supervisory Authority (瑞士金融市場監督管理局 FINMA)"
    LICENSE_TYPE = "Swiss Federal Open Public Information"
    IS_ACTIVE = True

    def _extract_domains(self, text: str | None) -> Set[str]:
        domains = set()
        if not text:
            return domains

        candidates = re.split(r'[\s,;\n\r\t/]+', str(text).strip())
        for raw in candidates:
            if not raw or "." not in raw:
                continue
            target = raw if re.match(r'^https?://', raw, re.IGNORECASE) else f"http://{raw}"
            try:
                parsed = urllib.parse.urlparse(target)
                domain = (parsed.hostname or "").lower().strip(".,;:)'\"")
                if domain and not domain.endswith(".finma.ch") and not domain.endswith(".admin.ch"):
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
        finma_id = f"identity--{deterministic_uuid('CH_FINMA_OFFICIAL')}"
        stix_objects.append({
            "type": "identity",
            "spec_version": "2.1",
            "id": finma_id,
            "created": PROJECT_EPOCH,
            "modified": PROJECT_EPOCH,
            "name": self.SOURCE_NAME,
            "identity_class": "government",
            "sectors": ["financial-services", "government"],
            "contact_information": "https://www.finma.ch"
        })

        raw_payload = None
        max_retries = 2
        req = urllib.request.Request(FINMA_API_ENDPOINT, headers=headers)
        for attempt in range(1, max_retries + 1):
            try:
                logging.info("正在請求瑞士 FINMA API (嘗試 %d/%d)...", attempt, max_retries)
                with urllib.request.urlopen(req, timeout=30) as response:
                    if response.status == 200:
                        raw_payload = json.loads(response.read().decode("utf-8"))
                        break
            except Exception as e:
                logging.warning("瑞士 FINMA API 嘗試 %d 失敗: %s", attempt, str(e))
                time.sleep(2)

        if not raw_payload:
            logging.warning("瑞士 FINMA API 暫時連線逾時，跳過即時拉取。")
            return stix_objects

        items = raw_payload if isinstance(raw_payload, list) else raw_payload.get("data", raw_payload.get("items", []))
        logging.info("瑞士 FINMA 取得原始警示記錄數: %d", len(items))

        for item in items:
            name = str(item.get("name") or item.get("company") or "Unauthorized Entity").strip()
            date_str = str(item.get("date") or item.get("added_date") or "").strip()
            details = str(item.get("address") or item.get("remarks") or "")
            website_str = str(item.get("internet") or item.get("website") or "")

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
            entity_id = f"identity--{deterministic_uuid(f'CH_FINMA_ENTITY_{name}')}"
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
            domains = self._extract_domains(f"{name} {website_str} {details}")
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
            report_seed = f"CH_FINMA_{clean_date}_{name}"
            report_id = f"report--{deterministic_uuid(report_seed)}"

            stix_objects.append({
                "type": "report",
                "spec_version": "2.1",
                "id": report_id,
                "created": pub_time,
                "modified": pub_time,
                "name": f"FINMA Warning: {name}",
                "description": "Unauthorized financial services provider on Swiss FINMA Warning List.",
                "published": pub_time,
                "confidence": 95,
                "x_veritas_license": self.LICENSE_TYPE,
                "external_references": [{
                    "source_name": "FINMA Warning List",
                    "url": "https://www.finma.ch/en/finma-public/warnungen/warning-list/"
                }],
                "object_refs": [finma_id, entity_id] + indicator_ids
            })

        return stix_objects
