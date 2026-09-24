"""
俄羅斯聯邦中央銀行 (Bank of Russia / CBR) 非法金融活動特徵實體清單適配器
資料來源：Bank of Russia Official Open Data (cbr.ru)
涵蓋：金融龐氏騙局、非法外匯經紀商、偽冒俄羅斯持牌金融機構網站
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

# 俄羅斯央行官方開放數據端點
RU_CBR_API_ENDPOINT = "https://www.cbr.ru/api/v1/illegal-financial-companies.json"
PROJECT_EPOCH = "2026-01-01T00:00:00.000Z"

class RUCBRBlacklistAdapter(BaseSourceAdapter):
    SOURCE_ID = "ru-cbr-illegal-companies"
    SOURCE_NAME = "Central Bank of the Russian Federation (俄羅斯聯邦中央銀行)"
    LICENSE_TYPE = "Bank of Russia Terms of Open Information"
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
                # 排除官方與俄羅斯央行網域名
                if domain and not domain.endswith(".cbr.ru") and not domain.endswith(".gov.ru"):
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

        # 1. 官方來源 Identity SDO (俄羅斯央行)
        cbr_id = f"identity--{deterministic_uuid('RU_CBR_OFFICIAL')}"
        stix_objects.append({
            "type": "identity",
            "spec_version": "2.1",
            "id": cbr_id,
            "created": PROJECT_EPOCH,
            "modified": PROJECT_EPOCH,
            "name": self.SOURCE_NAME,
            "identity_class": "government",
            "sectors": ["financial-services", "government"],
            "contact_information": "https://www.cbr.ru"
        })

        raw_payload = None
        max_retries = 2
        req = urllib.request.Request(RU_CBR_API_ENDPOINT, headers=headers)
        for attempt in range(1, max_retries + 1):
            try:
                logging.info("正在請求俄羅斯央行 API (嘗試 %d/%d)...", attempt, max_retries)
                with urllib.request.urlopen(req, timeout=30) as response:
                    if response.status == 200:
                        raw_payload = json.loads(response.read().decode("utf-8"))
                        break
            except Exception as e:
                logging.warning("俄羅斯央行 API 嘗試 %d 失敗: %s", attempt, str(e))
                time.sleep(2)

        if not raw_payload:
            logging.warning("俄羅斯央行連線逾時，跳過即時拉取。")
            return stix_objects

        records = raw_payload if isinstance(raw_payload, list) else raw_payload.get("data", raw_payload.get("items", []))
        logging.info("俄羅斯央行取得原始記錄數: %d", len(records))

        for rec in records:
            name = str(rec.get("name") or rec.get("entity_name") or "Illegal Financial Entity").strip()
            date_str = str(rec.get("date") or rec.get("added_date") or "").strip()
            website_str = str(rec.get("website") or rec.get("url") or "")
            sign_type = str(rec.get("sign_type") or "Signs of illegal activities in financial markets").strip()

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
            entity_id = f"identity--{deterministic_uuid(f'RU_CBR_ENTITY_{name}')}"
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
            report_seed = f"RU_CBR_{clean_date}_{name}"
            report_id = f"report--{deterministic_uuid(report_seed)}"

            stix_objects.append({
                "type": "report",
                "spec_version": "2.1",
                "id": report_id,
                "created": pub_time,
                "modified": pub_time,
                "name": f"Bank of Russia Warning: {name}",
                "description": f"Entity flagged by Bank of Russia: [{sign_type}].",
                "published": pub_time,
                "confidence": 95,
                "x_veritas_license": self.LICENSE_TYPE,
                "external_references": [{
                    "source_name": "Bank of Russia Blacklist",
                    "url": "https://www.cbr.ru/inside/warning-list/"
                }],
                "object_refs": [cbr_id, entity_id] + indicator_ids
            })

        return stix_objects
