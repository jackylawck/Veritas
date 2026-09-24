"""
新加坡金融管理局 (MAS) 投資者警示名單 (Investor Alert List - IAL) 適配器
資料授權：Singapore Open Data License
涵蓋：跨國未受規管金融實體、冒用星港兩地金融許可證的釣魚網站
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

MAS_IAL_ENDPOINT = "https://eservices.mas.gov.sg/IAL/api/v1/ial"
PROJECT_EPOCH = "2026-01-01T00:00:00.000Z"

class MASInvestorAlertAdapter(BaseSourceAdapter):
    SOURCE_ID = "sg-mas-investor-alert-list"
    SOURCE_NAME = "Monetary Authority of Singapore (新加坡金融管理局)"
    LICENSE_TYPE = "Singapore Open Data License"
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
                if domain and not domain.endswith(".gov.sg") and not domain.endswith(".mas.gov.sg"):
                    domains.add(domain)
            except Exception:
                continue
        return domains

    def fetch_and_parse(self) -> List[Dict[str, Any]]:
        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "application/json"
        }
        req = urllib.request.Request(MAS_IAL_ENDPOINT, headers=headers)
        raw_payload = None

        max_retries = 2
        for attempt in range(1, max_retries + 1):
            try:
                logging.info("正在請求 MAS IAL API (嘗試 %d/%d)...", attempt, max_retries)
                with urllib.request.urlopen(req, timeout=30) as response:
                    if response.status == 200:
                        raw_payload = json.loads(response.read().decode("utf-8"))
                        break
            except Exception as e:
                logging.warning("MAS API 嘗試 %d 失敗: %s", attempt, str(e))
                time.sleep(2)

        stix_objects = []
        # 1. 官方來源 Identity SDO
        mas_id = f"identity--{deterministic_uuid('MAS_OFFICIAL')}"
        stix_objects.append({
            "type": "identity",
            "spec_version": "2.1",
            "id": mas_id,
            "created": PROJECT_EPOCH,
            "modified": PROJECT_EPOCH,
            "name": self.SOURCE_NAME,
            "identity_class": "government",
            "sectors": ["financial-services", "government"],
            "contact_information": "https://www.mas.gov.sg"
        })

        if not raw_payload:
            logging.warning("MAS API 連線逾時，跳過即時拉取。")
            return stix_objects

        records = raw_payload.get("data", raw_payload.get("records", []))
        logging.info("MAS 取得原始記錄數: %d", len(records))

        for rec in records:
            name = str(rec.get("unregulatedPerson") or rec.get("entityName") or "Unregulated Entity").strip()
            date_str = str(rec.get("dateAdded") or "").strip()
            website_str = str(rec.get("website") or "")

            if date_str:
                try:
                    # 相容常見的 YYYY-MM-DD 或 DD MMM YYYY 格式
                    if len(date_str) == 10 and "-" in date_str:
                        pub_time = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
                    else:
                        pub_time = datetime.strptime(date_str, "%d %b %Y").replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
                except Exception:
                    pub_time = PROJECT_EPOCH
                    date_str = "unknown-date"
            else:
                pub_time = PROJECT_EPOCH
                date_str = "unknown-date"

            # 2. 被通報涉詐實體 Identity SDO
            victim_id = f"identity--{deterministic_uuid(f'MAS_ENTITY_{name}')}"
            stix_objects.append({
                "type": "identity",
                "spec_version": "2.1",
                "id": victim_id,
                "created": pub_time,
                "modified": pub_time,
                "name": name,
                "identity_class": "organization",
                "sectors": ["financial-services"]
            })

            # 3. 提取 IoC (Indicator)
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
            report_seed = f"MAS_IAL_{date_str}_{name}"
            report_id = f"report--{deterministic_uuid(report_seed)}"

            stix_objects.append({
                "type": "report",
                "spec_version": "2.1",
                "id": report_id,
                "created": pub_time,
                "modified": pub_time,
                "name": f"MAS Investor Alert: {name}",
                "description": "Unregulated entity mistakenly perceived as licensed, flagged by MAS.",
                "published": pub_time,
                "confidence": 95,
                "x_veritas_license": self.LICENSE_TYPE,
                "external_references": [{
                    "source_name": "MAS Investor Alert List",
                    "url": "https://www.mas.gov.sg/investor-alert-list"
                }],
                "object_refs": [mas_id, victim_id] + indicator_ids
            })

        return stix_objects
