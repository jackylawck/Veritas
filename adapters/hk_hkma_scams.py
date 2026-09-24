"""
香港金融管理局 (HKMA) 欺詐網站及偽冒電郵官方 API 適配器
資料授權：香港特區政府《開放數據許可協議》 (data.gov.hk)
"""
import json
import re
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, List, Set
from .base import BaseSourceAdapter, deterministic_uuid

HKMA_API_ENDPOINT = "https://api.hkma.gov.hk/public/bank-svf-info/fraudulent-bank-scams"
PROJECT_EPOCH = "2026-01-01T00:00:00.000Z"

class HKMAScamAdapter(BaseSourceAdapter):
    SOURCE_ID = "hk-hkma-fraudulent-bank-scams"
    SOURCE_NAME = "Hong Kong Monetary Authority (香港金融管理局)"
    LICENSE_TYPE = "Open Government Data License (data.gov.hk)"
    IS_ACTIVE = True

    def _extract_domains_from_field(self, field_value: str | None) -> Set[str]:
        """從 fraud_website_address 欄位清洗並提取規範化網域"""
        domains = set()
        if not field_value:
            return domains

        candidates = re.split(r'[\s,;\n\r]+', field_value.strip())
        for raw_url in candidates:
            if not raw_url:
                continue
            target = raw_url if re.match(r'^https?://', raw_url, re.IGNORECASE) else f"http://{raw_url}"
            try:
                parsed = urllib.parse.urlparse(target)
                domain = (parsed.hostname or "").lower().strip(".,;:)'\"")
                if domain and not domain.endswith(".gov.hk") and domain != "gov.hk":
                    domains.add(domain)
            except Exception:
                continue
        return domains

    def fetch_and_parse(self) -> List[Dict[str, Any]]:
        headers = {
            "User-Agent": "Veritas-OSINT-Mirror/1.0 (+https://github.com/jackylawck/veritas)"
        }
        req = urllib.request.Request(HKMA_API_ENDPOINT, headers=headers)
        with urllib.request.urlopen(req, timeout=15) as response:
            if response.status != 200:
                raise RuntimeError(f"HTTP {response.status} from HKMA API")
            raw_payload = json.loads(response.read().decode("utf-8"))

        records = raw_payload.get("result", {}).get("records", [])
        stix_objects = []

        # 1. 官方來源 Identity SDO（時間戳永久錨定於 PROJECT_EPOCH，確保冪等性）
        hkma_id = f"identity--{deterministic_uuid('HKMA_OFFICIAL')}"
        stix_objects.append({
            "type": "identity",
            "spec_version": "2.1",
            "id": hkma_id,
            "created": PROJECT_EPOCH,
            "modified": PROJECT_EPOCH,
            "name": self.SOURCE_NAME,
            "identity_class": "government",
            "sectors": ["financial-services", "government"],
            "contact_information": "https://www.hkma.gov.hk"
        })

        for item in records:
            issue_date = item.get("issue_date")
            alleged_name = (item.get("alleged_name") or "Unknown Entity").strip()
            pr_url = (item.get("pr_url") or "").strip()
            fraud_field = item.get("fraud_website_address")

            # 安全解析公報時間
            safe_date = (issue_date or "").strip()
            if safe_date:
                try:
                    pub_time = datetime.strptime(safe_date, "%Y-%m-%d").replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
                except Exception:
                    pub_time = PROJECT_EPOCH
                    safe_date = "unknown-date"
            else:
                pub_time = PROJECT_EPOCH
                safe_date = "unknown-date"

            # 2. 被冒用實體 Identity SDO (sectors 使用 STIX 標準開放詞彙 financial-services)
            victim_id = f"identity--{deterministic_uuid(f'BANK_{alleged_name}')}"
            stix_objects.append({
                "type": "identity",
                "spec_version": "2.1",
                "id": victim_id,
                "created": pub_time,
                "modified": pub_time,
                "name": alleged_name,
                "identity_class": "organization",
                "sectors": ["financial-services"]
            })

            # 3. 提取實體 IoC (Domain Indicators)
            domains = self._extract_domains_from_field(fraud_field)
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

            # 4. 關聯公報 Report SDO (安全拼接避免 None + str 崩潰)
            report_seed = f"HKMA_PR_{pr_url or (safe_date + '_' + alleged_name)}"
            report_id = f"report--{deterministic_uuid(report_seed)}"

            report_obj = {
                "type": "report",
                "spec_version": "2.1",
                "id": report_id,
                "created": pub_time,
                "modified": pub_time,
                "name": f"HKMA Fraud Alert: {alleged_name}",
                "published": pub_time,
                "confidence": 90,
                "x_veritas_license": self.LICENSE_TYPE,
                "object_refs": [hkma_id, victim_id] + indicator_ids
            }
            if pr_url:
                report_obj["external_references"] = [{"source_name": "HKMA Press Release", "url": pr_url}]

            stix_objects.append(report_obj)

        return stix_objects
