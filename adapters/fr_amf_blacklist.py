"""
法國金融市場管理局 (AMF) 未授權投資平台與冒名金融實體黑名單適配器
資料授權：Open Licence (Etalab / data.gouv.fr)
涵蓋：假冒持牌經紀商、未受監管加密資產交易平台 (DASP)、外匯投資欺詐網域
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

# 法國官方開放數據 data.gouv.fr 提供的 AMF 黑名單端點
FR_AMF_API_ENDPOINT = "https://data.gouv.fr/api/1/datasets/listes-noires-de-lautorite-des-marches-financiers-amf/resources"
PROJECT_EPOCH = "2026-01-01T00:00:00.000Z"

class FRAMFBlacklistAdapter(BaseSourceAdapter):
    SOURCE_ID = "fr-amf-blacklist"
    SOURCE_NAME = "Autorité des Marchés Financiers (法國金融市場管理局)"
    LICENSE_TYPE = "Licence Ouverte / Open Licence 2.0 (data.gouv.fr)"
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
                if domain and not domain.endswith(".gouv.fr") and not domain.endswith(".amf-france.org"):
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
        amf_id = f"identity--{deterministic_uuid('FR_AMF_OFFICIAL')}"
        stix_objects.append({
            "type": "identity",
            "spec_version": "2.1",
            "id": amf_id,
            "created": PROJECT_EPOCH,
            "modified": PROJECT_EPOCH,
            "name": self.SOURCE_NAME,
            "identity_class": "government",
            "sectors": ["financial-services", "government"],
            "contact_information": "https://www.amf-france.org"
        })

        raw_payload = None
        max_retries = 2
        req = urllib.request.Request(FR_AMF_API_ENDPOINT, headers=headers)
        for attempt in range(1, max_retries + 1):
            try:
                logging.info("正在請求法國 AMF API (嘗試 %d/%d)...", attempt, max_retries)
                with urllib.request.urlopen(req, timeout=30) as response:
                    if response.status == 200:
                        raw_payload = json.loads(response.read().decode("utf-8"))
                        break
            except Exception as e:
                logging.warning("法國 AMF API 嘗試 %d 失敗: %s", attempt, str(e))
                time.sleep(2)

        if not raw_payload:
            logging.warning("AMF API 暫時連線逾時，跳過即時拉取。")
            return stix_objects

        resources = raw_payload if isinstance(raw_payload, list) else raw_payload.get("data", [])
        logging.info("法國 AMF 取得資源清單數: %d", len(resources))

        # 解析 AMF 歷史黑名單條目
        for item in resources:
            title = str(item.get("title") or item.get("name") or "AMF Blacklisted Entity").strip()
            date_str = str(item.get("published") or item.get("created_at") or "").strip()
            url_val = str(item.get("url") or "")

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

            # 涉案實體 Identity SDO
            entity_id = f"identity--{deterministic_uuid(f'FR_AMF_ENTITY_{title}')}"
            stix_objects.append({
                "type": "identity",
                "spec_version": "2.1",
                "id": entity_id,
                "created": pub_time,
                "modified": pub_time,
                "name": title,
                "identity_class": "organization",
                "sectors": ["financial-services"]
            })

            # 提取惡意網域
            domains = self._extract_domains(url_val)
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

            # 生成 Report SDO
            report_seed = f"FR_AMF_{clean_date}_{title[:30]}"
            report_id = f"report--{deterministic_uuid(report_seed)}"

            stix_objects.append({
                "type": "report",
                "spec_version": "2.1",
                "id": report_id,
                "created": pub_time,
                "modified": pub_time,
                "name": f"AMF Alert: {title}",
                "description": "Unauthorized financial or crypto investment platform on the official AMF blacklist (EU/France).",
                "published": pub_time,
                "confidence": 95,
                "x_veritas_license": self.LICENSE_TYPE,
                "external_references": [{
                    "source_name": "AMF Blacklist Portal",
                    "url": "https://www.amf-france.org/en/warnings/blacklists"
                }],
                "object_refs": [amf_id, entity_id] + indicator_ids
            })

        return stix_objects
