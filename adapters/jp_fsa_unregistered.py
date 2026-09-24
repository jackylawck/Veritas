"""
日本金融廳 (FSA) 無登録で金融商品取引業等を行う者（未註冊業者清單）適配器
資料授權：Government of Japan Open Data Terms of Use (data.go.jp)
涵蓋：假冒日本持牌金融機構、未經許可外匯保證金業者、AI 偽冒名流投資平台
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

# 日本政府開放數據 / 金融廳官方開放端點
JP_FSA_API_ENDPOINT = "https://www.fsa.go.jp/menkyo/menkyoj/unregistered-firms.json"
PROJECT_EPOCH = "2026-01-01T00:00:00.000Z"

class JPFSAWarningAdapter(BaseSourceAdapter):
    SOURCE_ID = "jp-fsa-unregistered-firms"
    SOURCE_NAME = "Financial Services Agency of Japan (日本金融廳)"
    LICENSE_TYPE = "Government of Japan Open Data License (data.go.jp)"
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
                if domain and not domain.endswith(".go.jp") and not domain.endswith(".fsa.go.jp"):
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
        fsa_id = f"identity--{deterministic_uuid('JP_FSA_OFFICIAL')}"
        stix_objects.append({
            "type": "identity",
            "spec_version": "2.1",
            "id": fsa_id,
            "created": PROJECT_EPOCH,
            "modified": PROJECT_EPOCH,
            "name": self.SOURCE_NAME,
            "identity_class": "government",
            "sectors": ["financial-services", "government"],
            "contact_information": "https://www.fsa.go.jp"
        })

        raw_payload = None
        max_retries = 2
        req = urllib.request.Request(JP_FSA_API_ENDPOINT, headers=headers)
        for attempt in range(1, max_retries + 1):
            try:
                logging.info("正在請求日本 FSA API (嘗試 %d/%d)...", attempt, max_retries)
                with urllib.request.urlopen(req, timeout=30) as response:
                    if response.status == 200:
                        raw_payload = json.loads(response.read().decode("utf-8"))
                        break
            except Exception as e:
                logging.warning("日本 FSA API 嘗試 %d 失敗: %s", attempt, str(e))
                time.sleep(2)

        if not raw_payload:
            logging.warning("日本 FSA API 暫時連線逾時，跳過即時拉取。")
            return stix_objects

        items = raw_payload if isinstance(raw_payload, list) else raw_payload.get("firms", raw_payload.get("data", []))
        logging.info("日本 FSA 取得原始警示記錄數: %d", len(items))

        for item in items:
            name = str(item.get("name") or item.get("firm_name") or "Unregistered Entity").strip()
            date_str = str(item.get("date") or item.get("publication_date") or "").strip()
            website_str = str(item.get("website") or item.get("url") or "")

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

            # 2. 涉案實體 Identity SDO
            entity_id = f"identity--{deterministic_uuid(f'JP_FSA_ENTITY_{name}')}"
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
            report_seed = f"JP_FSA_{clean_date}_{name}"
            report_id = f"report--{deterministic_uuid(report_seed)}"

            stix_objects.append({
                "type": "report",
                "spec_version": "2.1",
                "id": report_id,
                "created": pub_time,
                "modified": pub_time,
                "name": f"FSA Japan Warning: {name}",
                "description": "Unregistered financial instrument business entity flagged by Financial Services Agency of Japan.",
                "published": pub_time,
                "confidence": 95,
                "x_veritas_license": self.LICENSE_TYPE,
                "external_references": [{
                    "source_name": "FSA Japan Unregistered Entities",
                    "url": "https://www.fsa.go.jp/menkyo/menkyoj/musyoroku.html"
                }],
                "object_refs": [fsa_id, entity_id] + indicator_ids
            })

        return stix_objects
