"""
加拿大安大略省證券委員會 (OSC) 投資者警示名單適配器
資料授權：Ontario Open Data Directive
涵蓋：北美冒名金融機構、未經許可外匯交易商、殺豬盤加密貨幣詐騙平台
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

OSC_WARNING_API_ENDPOINT = "https://www.osc.ca/api/v1/investor-warnings.json"
PROJECT_EPOCH = "2026-01-01T00:00:00.000Z"

class OSCWarningAdapter(BaseSourceAdapter):
    SOURCE_ID = "ca-osc-warning-list"
    SOURCE_NAME = "Ontario Securities Commission (加拿大安大略省證券委員會)"
    LICENSE_TYPE = "Ontario Open Data Directive"
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
                if domain and not domain.endswith(".ca") and not domain.endswith(".osc.ca") and not domain.endswith(".gov.on.ca"):
                    domains.add(domain)
                elif domain and not domain.endswith(".osc.ca") and not domain.endswith(".gov.on.ca"):
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
        osc_id = f"identity--{deterministic_uuid('CA_OSC_OFFICIAL')}"
        stix_objects.append({
            "type": "identity",
            "spec_version": "2.1",
            "id": osc_id,
            "created": PROJECT_EPOCH,
            "modified": PROJECT_EPOCH,
            "name": self.SOURCE_NAME,
            "identity_class": "government",
            "sectors": ["financial-services", "government"],
            "contact_information": "https://www.osc.ca"
        })

        raw_payload = None
        max_retries = 2
        req = urllib.request.Request(OSC_WARNING_API_ENDPOINT, headers=headers)
        for attempt in range(1, max_retries + 1):
            try:
                logging.info("正在請求加拿大 OSC API (嘗試 %d/%d)...", attempt, max_retries)
                with urllib.request.urlopen(req, timeout=30) as response:
                    if response.status == 200:
                        raw_payload = json.loads(response.read().decode("utf-8"))
                        break
            except Exception as e:
                logging.warning("加拿大 OSC API 嘗試 %d 失敗: %s", attempt, str(e))
                time.sleep(2)

        if not raw_payload:
            logging.warning("OSC API 暫時連線逾時，跳過即時拉取。")
            return stix_objects

        items = raw_payload if isinstance(raw_payload, list) else raw_payload.get("data", raw_payload.get("items", []))
        logging.info("加拿大 OSC 取得原始警示記錄數: %d", len(items))

        for item in items:
            name = str(item.get("name") or item.get("firm_name") or "Unregistered Entity").strip()
            date_str = str(item.get("date") or item.get("warning_date") or "").strip()
            website_str = str(item.get("website") or item.get("url") or "")
            reason = str(item.get("reason") or "Soliciting investments without statutory registration in Ontario.").strip()

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
            entity_id = f"identity--{deterministic_uuid(f'CA_OSC_ENTITY_{name}')}"
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
            report_seed = f"CA_OSC_{clean_date}_{name}"
            report_id = f"report--{deterministic_uuid(report_seed)}"

            stix_objects.append({
                "type": "report",
                "spec_version": "2.1",
                "id": report_id,
                "created": pub_time,
                "modified": pub_time,
                "name": f"OSC Warning: {name}",
                "description": reason[:300],
                "published": pub_time,
                "confidence": 95,
                "x_veritas_license": self.LICENSE_TYPE,
                "external_references": [{
                    "source_name": "OSC Warning List",
                    "url": "https://www.osc.ca/en/investors/warnings"
                }],
                "object_refs": [osc_id, entity_id] + indicator_ids
            })

        return stix_objects
