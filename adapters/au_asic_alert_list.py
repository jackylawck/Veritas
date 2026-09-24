"""
澳洲證券與投資委員會 (ASIC) 投資者警示清單 (Investor Alert List) 適配器
資料授權：Australian Government Open Data / Moneysmart terms
涵蓋：未持有澳洲金融服務牌照 (AFSL) 之非法金融中介、冒名持牌券商 (Clone Firms)
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

ASIC_API_ENDPOINT = "https://moneysmart.gov.au/api/v1/investor-alert-list.json"
PROJECT_EPOCH = "2026-01-01T00:00:00.000Z"

class ASICAlertAdapter(BaseSourceAdapter):
    SOURCE_ID = "au-asic-investor-alert-list"
    SOURCE_NAME = "Australian Securities and Investments Commission (澳洲證券與投資委員會 ASIC)"
    LICENSE_TYPE = "Australian Government Open Access Terms"
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
                if domain and not domain.endswith(".asic.gov.au") and not domain.endswith(".gov.au"):
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
        asic_id = f"identity--{deterministic_uuid('AU_ASIC_OFFICIAL')}"
        stix_objects.append({
            "type": "identity",
            "spec_version": "2.1",
            "id": asic_id,
            "created": PROJECT_EPOCH,
            "modified": PROJECT_EPOCH,
            "name": self.SOURCE_NAME,
            "identity_class": "government",
            "sectors": ["financial-services", "government"],
            "contact_information": "https://asic.gov.au"
        })

        raw_payload = None
        max_retries = 2
        req = urllib.request.Request(ASIC_API_ENDPOINT, headers=headers)
        for attempt in range(1, max_retries + 1):
            try:
                logging.info("正在請求澳洲 ASIC API (嘗試 %d/%d)...", attempt, max_retries)
                with urllib.request.urlopen(req, timeout=30) as response:
                    if response.status == 200:
                        raw_payload = json.loads(response.read().decode("utf-8"))
                        break
            except Exception as e:
                logging.warning("澳洲 ASIC API 嘗試 %d 失敗: %s", attempt, str(e))
                time.sleep(2)

        if not raw_payload:
            logging.warning("澳洲 ASIC API 暫時連線逾時，跳過即時拉取。")
            return stix_objects

        records = raw_payload if isinstance(raw_payload, list) else raw_payload.get("items", raw_payload.get("data", []))
        logging.info("澳洲 ASIC 取得原始警示記錄數: %d", len(records))

        for rec in records:
            name = str(rec.get("name") or rec.get("entity_name") or "Unlicensed Entity").strip()
            date_str = str(rec.get("date_added") or rec.get("date") or "").strip()
            website_str = str(rec.get("website") or rec.get("url") or "")

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
            entity_id = f"identity--{deterministic_uuid(f'AU_ASIC_ENTITY_{name}')}"
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
            domains = self._extract_domains(f"{name} {website_str}")
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
            report_seed = f"AU_ASIC_{clean_date}_{name}"
            report_id = f"report--{deterministic_uuid(report_seed)}"

            stix_objects.append({
                "type": "report",
                "spec_version": "2.1",
                "id": report_id,
                "created": pub_time,
                "modified": pub_time,
                "name": f"ASIC Alert: {name}",
                "description": "Entity operating or offering financial services without statutory license in Australia.",
                "published": pub_time,
                "confidence": 95,
                "x_veritas_license": self.LICENSE_TYPE,
                "external_references": [{
                    "source_name": "ASIC Moneysmart Investor Alert List",
                    "url": "https://moneysmart.gov.au/check-and-report-scams/investor-alert-list"
                }],
                "object_refs": [asic_id, entity_id] + indicator_ids
            })

        return stix_objects
