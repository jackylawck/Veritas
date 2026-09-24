"""
美國商品期貨交易委員會 (CFTC) RED List (Registration Deficient List) 適配器
資料來源：U.S. Commodity Futures Trading Commission Open Data
涵蓋：未在美註冊涉嫌招攬外匯、二元期權與虛擬資產衍生品的欺詐平台
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

# 美國聯邦政府開放資料 CFTC RED List 端點
US_CFTC_RED_API_ENDPOINT = "https://www.cftc.gov/api/v1/red-list.json"
PROJECT_EPOCH = "2026-01-01T00:00:00.000Z"

class CFTCRedListAdapter(BaseSourceAdapter):
    SOURCE_ID = "us-cftc-red-list"
    SOURCE_NAME = "U.S. Commodity Futures Trading Commission (美國商品期貨交易委員會)"
    LICENSE_TYPE = "U.S. Public Domain / Open Data"
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
                if domain and not domain.endswith(".gov") and not domain.endswith(".cftc.gov"):
                    domains.add(domain)
            except Exception:
                continue
        return domains

    def fetch_and_parse(self) -> List[Dict[str, Any]]:
        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "application/json"
        }
        req = urllib.request.Request(US_CFTC_RED_API_ENDPOINT, headers=headers)
        raw_payload = None

        max_retries = 2
        for attempt in range(1, max_retries + 1):
            try:
                logging.info("正在請求美國 CFTC RED List API (嘗試 %d/%d)...", attempt, max_retries)
                with urllib.request.urlopen(req, timeout=30) as response:
                    if response.status == 200:
                        raw_payload = json.loads(response.read().decode("utf-8"))
                        break
            except Exception as e:
                logging.warning("美國 CFTC API 嘗試 %d 失敗: %s", attempt, str(e))
                time.sleep(2)

        stix_objects = []
        # 1. 官方來源 Identity SDO
        cftc_id = f"identity--{deterministic_uuid('US_CFTC_OFFICIAL')}"
        stix_objects.append({
            "type": "identity",
            "spec_version": "2.1",
            "id": cftc_id,
            "created": PROJECT_EPOCH,
            "modified": PROJECT_EPOCH,
            "name": self.SOURCE_NAME,
            "identity_class": "government",
            "sectors": ["financial-services", "government"],
            "contact_information": "https://www.cftc.gov"
        })

        if not raw_payload:
            logging.warning("CFTC API 連線逾時，跳過即時拉取。")
            return stix_objects

        records = raw_payload if isinstance(raw_payload, list) else raw_payload.get("data", [])
        logging.info("美國 CFTC 取得原始記錄數: %d", len(records))

        for rec in records:
            name = str(rec.get("name") or rec.get("entity_name") or "Registration Deficient Entity").strip()
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
            victim_id = f"identity--{deterministic_uuid(f'US_CFTC_ENTITY_{name}')}"
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

            # 3. 提取 IoC (Indicators)
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
            report_seed = f"US_CFTC_{clean_date}_{name}"
            report_id = f"report--{deterministic_uuid(report_seed)}"

            stix_objects.append({
                "type": "report",
                "spec_version": "2.1",
                "id": report_id,
                "created": pub_time,
                "modified": pub_time,
                "name": f"CFTC RED Alert: {name}",
                "description": "Entity on the CFTC RED List soliciting U.S. customers without required registration.",
                "published": pub_time,
                "confidence": 95,
                "x_veritas_license": self.LICENSE_TYPE,
                "external_references": [{
                    "source_name": "CFTC RED List",
                    "url": "https://www.cftc.gov/check"
                }],
                "object_refs": [cftc_id, victim_id] + indicator_ids
            })

        return stix_objects
