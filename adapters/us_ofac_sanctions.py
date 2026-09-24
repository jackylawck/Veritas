"""
美國財政部外國資產控制辦公室 (OFAC) 特別指定國民清單 (SDN) 涉詐與網絡犯罪適配器
資料授權：U.S. Department of the Treasury Public Domain
涵蓋：跨國網絡犯罪集團、勒索洗錢平台、惡意虛擬貨幣服務商
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

# 美國財政部官方 OFAC SDN 結構化開放端點
OFAC_API_ENDPOINT = "https://sanctionssearch.ofac.treas.gov/api/v1/sdn-cyber.json"
PROJECT_EPOCH = "2026-01-01T00:00:00.000Z"

class USOFACSanctionsAdapter(BaseSourceAdapter):
    SOURCE_ID = "us-ofac-cyber-sanctions"
    SOURCE_NAME = "U.S. Department of the Treasury OFAC (美國財政部外國資產控制辦公室)"
    LICENSE_TYPE = "U.S. Public Domain"
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
                if domain and not domain.endswith(".treasury.gov") and not domain.endswith(".gov"):
                    domains.add(domain)
            except Exception:
                continue
        return domains

    def fetch_and_parse(self) -> List[Dict[str, Any]]:
        headers = {
            "User-Agent": "Veritas-AML-Mirror/1.0 (+https://github.com/jackylawck/Veritas)",
            "Accept": "application/json"
        }
        stix_objects = []

        # 1. 官方來源 Identity SDO (OFAC)
        ofac_id = f"identity--{deterministic_uuid('US_OFAC_OFFICIAL')}"
        stix_objects.append({
            "type": "identity",
            "spec_version": "2.1",
            "id": ofac_id,
            "created": PROJECT_EPOCH,
            "modified": PROJECT_EPOCH,
            "name": self.SOURCE_NAME,
            "identity_class": "government",
            "sectors": ["government", "financial-services"],
            "contact_information": "https://home.treasury.gov/policy-issues/office-of-foreign-assets-control-sanctions"
        })

        raw_payload = None
        max_retries = 2
        req = urllib.request.Request(OFAC_API_ENDPOINT, headers=headers)
        for attempt in range(1, max_retries + 1):
            try:
                logging.info("正在請求 OFAC 制裁名單 (嘗試 %d/%d)...", attempt, max_retries)
                with urllib.request.urlopen(req, timeout=35) as response:
                    if response.status == 200:
                        raw_payload = json.loads(response.read().decode("utf-8"))
                        break
            except Exception as e:
                logging.warning("OFAC API 嘗試 %d 失敗: %s", attempt, str(e))
                time.sleep(2)

        if not raw_payload:
            logging.warning("OFAC API 暫時連線逾時，跳過即時拉取。")
            return stix_objects

        items = raw_payload if isinstance(raw_payload, list) else raw_payload.get("entries", [])
        logging.info("OFAC 取得原始制裁實體數: %d", len(items))

        for item in items:
            entity_name = str(item.get("name") or "Sanctioned Cyber Entity").strip()
            date_str = str(item.get("date") or item.get("publish_date") or "").strip()
            remarks = str(item.get("remarks") or item.get("program") or "")
            website_str = str(item.get("website") or item.get("id_details") or "")

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

            # 2. 被制裁實體 Identity SDO
            sanctioned_id = f"identity--{deterministic_uuid(f'OFAC_SDN_{entity_name}')}"
            stix_objects.append({
                "type": "identity",
                "spec_version": "2.1",
                "id": sanctioned_id,
                "created": pub_time,
                "modified": pub_time,
                "name": entity_name,
                "identity_class": "organization",
                "sectors": ["financial-services"]
            })

            # 3. 提取涉案網域 IoC
            domains = self._extract_domains(f"{website_str} {remarks}")
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
                    "confidence": 99  # OFAC 制裁名單具最高法律置信度
                })

            # 4. 生成 Report SDO
            report_seed = f"US_OFAC_{clean_date}_{entity_name}"
            report_id = f"report--{deterministic_uuid(report_seed)}"

            stix_objects.append({
                "type": "report",
                "spec_version": "2.1",
                "id": report_id,
                "created": pub_time,
                "modified": pub_time,
                "name": f"OFAC Sanctions Alert: {entity_name}",
                "description": f"Entity designated under U.S. sanctions programs: {remarks[:200]}",
                "published": pub_time,
                "confidence": 99,
                "x_veritas_license": self.LICENSE_TYPE,
                "external_references": [{
                    "source_name": "OFAC Sanctions Search",
                    "url": "https://sanctionssearch.ofac.treas.gov"
                }],
                "object_refs": [ofac_id, sanctioned_id] + indicator_ids
            })

        return stix_objects
