"""
香港警務處網絡安全及科技罪案調查科 (CSTCB) 防騙視伏器 (Scameter) 開放資料適配器
資料授權：香港特區政府《開放數據許可協議》 (data.gov.hk)
涵蓋：經警方調查確立之高危欺詐網址、冒名機構釣魚站
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

# 香港政府開放資料平台警務處防騙視伏器公開端點
HK_POLICE_API_ENDPOINT = "https://api.data.gov.hk/v1/historical-archive/get-file?url=https%3A%2F%2Fcyberdefender.hk%2Fapi%2Fpublic%2Fscam-list"
PROJECT_EPOCH = "2026-01-01T00:00:00.000Z"

class HKPoliceScameterAdapter(BaseSourceAdapter):
    SOURCE_ID = "hk-police-cstcb-scameter"
    SOURCE_NAME = "Hong Kong Police Force CSTCB (香港警務處網絡安全及科技罪案調查科)"
    LICENSE_TYPE = "Open Government Data License (data.gov.hk)"
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
                if domain and not domain.endswith(".gov.hk") and not domain.endswith(".police.gov.hk"):
                    domains.add(domain)
            except Exception:
                continue
        return domains

    def fetch_and_parse(self) -> List[Dict[str, Any]]:
        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "application/json"
        }
        req = urllib.request.Request(HK_POLICE_API_ENDPOINT, headers=headers)
        raw_payload = None

        max_retries = 2
        for attempt in range(1, max_retries + 1):
            try:
                logging.info("正在請求香港警務處防騙端點 (嘗試 %d/%d)...", attempt, max_retries)
                with urllib.request.urlopen(req, timeout=30) as response:
                    if response.status == 200:
                        raw_payload = json.loads(response.read().decode("utf-8"))
                        break
            except Exception as e:
                logging.warning("香港警務處端點嘗試 %d 失敗: %s", attempt, str(e))
                time.sleep(2)

        stix_objects = []
        # 1. 官方來源 Identity SDO
        police_id = f"identity--{deterministic_uuid('HKPF_CSTCB_OFFICIAL')}"
        stix_objects.append({
            "type": "identity",
            "spec_version": "2.1",
            "id": police_id,
            "created": PROJECT_EPOCH,
            "modified": PROJECT_EPOCH,
            "name": self.SOURCE_NAME,
            "identity_class": "government",
            "sectors": ["government"],
            "contact_information": "https://cyberdefender.hk"
        })

        if not raw_payload:
            logging.warning("警務處端點暫時無法連線，跳過即時拉取。")
            return stix_objects

        items = raw_payload.get("data", raw_payload.get("records", []))
        logging.info("香港警務處防騙視伏器取得原始記錄數: %d", len(items))

        for item in items:
            raw_target = str(item.get("target") or item.get("url") or item.get("suspicious_url") or "").strip()
            date_str = str(item.get("date") or item.get("created_at") or "").strip()
            category = str(item.get("category") or "Financial / Phishing Scam").strip()

            if not raw_target:
                continue

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

            domains = self._extract_domains(raw_target)
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
                    "confidence": 95
                })

            report_seed = f"HKPF_SCAMETER_{clean_date}_{raw_target[:50]}"
            report_id = f"report--{deterministic_uuid(report_seed)}"

            stix_objects.append({
                "type": "report",
                "spec_version": "2.1",
                "id": report_id,
                "created": pub_time,
                "modified": pub_time,
                "name": f"CyberDefender Alert: {list(domains)[0]}",
                "description": f"Verified high-risk fraudulent infrastructure [{category}] flagged by HKPF CSTCB.",
                "published": pub_time,
                "confidence": 95,
                "x_veritas_license": self.LICENSE_TYPE,
                "external_references": [{
                    "source_name": "CyberDefender Scameter",
                    "url": "https://cyberdefender.hk"
                }],
                "object_refs": [police_id] + indicator_ids
            })

        return stix_objects
