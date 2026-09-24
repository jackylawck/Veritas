"""
德國聯邦金融監管局 (BaFin) 消費者警示與未授權金融業務名單適配器
資料授權：Federal Government of Germany Open Data / BaFin Terms
涵蓋：未經授權跨國銀行業務、偽冒金融經紀商、可疑加密資產衍生品招攬平台
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

# 德國 BaFin 官方消費者警示 API 端點
BAFIN_WARNINGS_API_ENDPOINT = "https://www.bafin.de/api/v1/consumer-warnings.json"
PROJECT_EPOCH = "2026-01-01T00:00:00.000Z"

class BaFinWarningAdapter(BaseSourceAdapter):
    SOURCE_ID = "de-bafin-consumer-warnings"
    SOURCE_NAME = "Federal Financial Supervisory Authority (德國聯邦金融監管局 BaFin)"
    LICENSE_TYPE = "Germany Open Government License / BaFin Terms"
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
                if domain and not domain.endswith(".bafin.de") and not domain.endswith(".bund.de"):
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
        bafin_id = f"identity--{deterministic_uuid('DE_BAFIN_OFFICIAL')}"
        stix_objects.append({
            "type": "identity",
            "spec_version": "2.1",
            "id": bafin_id,
            "created": PROJECT_EPOCH,
            "modified": PROJECT_EPOCH,
            "name": self.SOURCE_NAME,
            "identity_class": "government",
            "sectors": ["financial-services", "government"],
            "contact_information": "https://www.bafin.de"
        })

        raw_payload = None
        max_retries = 2
        req = urllib.request.Request(BAFIN_WARNINGS_API_ENDPOINT, headers=headers)
        for attempt in range(1, max_retries + 1):
            try:
                logging.info("正在請求德國 BaFin API (嘗試 %d/%d)...", attempt, max_retries)
                with urllib.request.urlopen(req, timeout=30) as response:
                    if response.status == 200:
                        raw_payload = json.loads(response.read().decode("utf-8"))
                        break
            except Exception as e:
                logging.warning("德國 BaFin API 嘗試 %d 失敗: %s", attempt, str(e))
                time.sleep(2)

        if not raw_payload:
            logging.warning("德國 BaFin API 暫時連線逾時，跳過即時拉取。")
            return stix_objects

        items = raw_payload if isinstance(raw_payload, list) else raw_payload.get("warnings", raw_payload.get("data", []))
        logging.info("德國 BaFin 取得原始警示記錄數: %d", len(items))

        for item in items:
            title = str(item.get("title") or item.get("subject") or "Unauthorized Financial Provider").strip()
            date_str = str(item.get("date") or item.get("published_at") or "").strip()
            details = str(item.get("description") or item.get("text") or "")
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

            # 2. 涉詐實體 Identity SDO
            entity_id = f"identity--{deterministic_uuid(f'DE_BAFIN_ENTITY_{title}')}"
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

            # 3. 提取惡意網域 IoC (兼顧主網站與說明文本中的 URL)
            domains = self._extract_domains(f"{website_str} {details}")
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
            report_seed = f"DE_BAFIN_{clean_date}_{title[:30]}"
            report_id = f"report--{deterministic_uuid(report_seed)}"

            stix_objects.append({
                "type": "report",
                "spec_version": "2.1",
                "id": report_id,
                "created": pub_time,
                "modified": pub_time,
                "name": f"BaFin Alert: {title}",
                "description": details[:300] if details else "Unauthorized financial entity flagged by German BaFin.",
                "published": pub_time,
                "confidence": 95,
                "x_veritas_license": self.LICENSE_TYPE,
                "external_references": [{
                    "source_name": "BaFin Consumer Warnings",
                    "url": "https://www.bafin.de/EN/Verbraucher/Aktuelles/Verbraucherwarnungen/verbraucherwarnungen_node_en.html"
                }],
                "object_refs": [bafin_id, entity_id] + indicator_ids
            })

        return stix_objects
