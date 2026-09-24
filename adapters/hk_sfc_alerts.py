"""
香港證券及期貨事務監察委員會 (SFC) 可疑網站及無牌公司名單適配器
資料來源：香港證監會官方開放數據 / data.gov.hk
涵蓋：假冒持牌機構、可疑虛擬資產交易平台 (VATP)、Deepfake 投資騙局網域
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

# 香港證監會無牌公司及可疑網站官方開放 API
SFC_API_ENDPOINT = "https://www.sfc.hk/alertlist-api/api/v1/alert-list"
PROJECT_EPOCH = "2026-01-01T00:00:00.000Z"

class SFCAlertAdapter(BaseSourceAdapter):
    SOURCE_ID = "hk-sfc-unlicensed-alert-list"
    SOURCE_NAME = "Securities and Futures Commission (香港證券及期貨事務監察委員會)"
    LICENSE_TYPE = "Open Government Data License (data.gov.hk)"
    IS_ACTIVE = True

    def _extract_domains(self, text: str | None) -> Set[str]:
        """清洗提取網域並過濾官方與無效主機名"""
        domains = set()
        if not text:
            return domains

        # 分割可能包含的多重 URL 或文字
        candidates = re.split(r'[\s,;\n\r\t]+', str(text).strip())
        for raw in candidates:
            if not raw or "." not in raw:
                continue
            target = raw if re.match(r'^https?://', raw, re.IGNORECASE) else f"http://{raw}"
            try:
                parsed = urllib.parse.urlparse(target)
                domain = (parsed.hostname or "").lower().strip(".,;:)'\"")
                if domain and not domain.endswith(".gov.hk") and not domain.endswith(".sfc.hk") and domain != "sfc.hk":
                    domains.add(domain)
            except Exception:
                continue
        return domains

    def fetch_and_parse(self) -> List[Dict[str, Any]]:
        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "application/json, text/plain, */*"
        }
        req = urllib.request.Request(SFC_API_ENDPOINT, headers=headers)
        raw_payload = None

        max_retries = 2
        for attempt in range(1, max_retries + 1):
            try:
                logging.info("正在請求 SFC API (嘗試 %d/%d)...", attempt, max_retries)
                with urllib.request.urlopen(req, timeout=30) as response:
                    if response.status == 200:
                        raw_payload = json.loads(response.read().decode("utf-8"))
                        break
            except Exception as e:
                logging.warning("SFC API 嘗試 %d 失敗: %s", attempt, str(e))
                time.sleep(2)

        stix_objects = []
        # 1. 官方來源 Identity SDO (固定 PROJECT_EPOCH，確保冪等)
        sfc_id = f"identity--{deterministic_uuid('SFC_OFFICIAL')}"
        stix_objects.append({
            "type": "identity",
            "spec_version": "2.1",
            "id": sfc_id,
            "created": PROJECT_EPOCH,
            "modified": PROJECT_EPOCH,
            "name": self.SOURCE_NAME,
            "identity_class": "government",
            "sectors": ["financial-services", "government"],
            "contact_information": "https://www.sfc.hk"
        })

        if not raw_payload:
            logging.warning("SFC API 暫時連線逾時，跳過即時拉取。")
            return stix_objects

        items = raw_payload if isinstance(raw_payload, list) else raw_payload.get("items", raw_payload.get("records", []))
        logging.info("SFC 取得原始警示記錄數: %d", len(items))

        for item in items:
            name = str(item.get("name") or item.get("entityName") or "Suspicious Entity").strip()
            date_str = str(item.get("date") or item.get("addedDate") or "").strip()
            website_str = str(item.get("website") or item.get("websites") or "")
            sfc_remarks = str(item.get("remarks") or "").strip()

            if date_str:
                try:
                    pub_time = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
                except Exception:
                    pub_time = PROJECT_EPOCH
                    date_str = "unknown-date"
            else:
                pub_time = PROJECT_EPOCH
                date_str = "unknown-date"

            # 2. 被通報涉詐實體 Identity SDO
            entity_id = f"identity--{deterministic_uuid(f'SFC_ENTITY_{name}')}"
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
            report_seed = f"SFC_ALERT_{date_str}_{name}"
            report_id = f"report--{deterministic_uuid(report_seed)}"

            stix_objects.append({
                "type": "report",
                "spec_version": "2.1",
                "id": report_id,
                "created": pub_time,
                "modified": pub_time,
                "name": f"SFC Alert: {name}",
                "description": sfc_remarks or "Unlicensed entity / suspicious website flagged by Hong Kong SFC.",
                "published": pub_time,
                "confidence": 95,
                "x_veritas_license": self.LICENSE_TYPE,
                "external_references": [{
                    "source_name": "SFC Alert List",
                    "url": "https://www.sfc.hk/en/alert-list"
                }],
                "object_refs": [sfc_id, entity_id] + indicator_ids
            })

        return stix_objects
