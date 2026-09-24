"""
中國互聯網聯合闢謠平台 (中央網信辦違法和不良信息舉報中心) 專項適配器
資料來源：中央網信辦主管 / 中國互聯網聯合闢謠平台 (piyao.org.cn) 公開公報
涵蓋：涉企商譽冒名、AI 深度偽造公報、冒用國家機關與金融機構欺詐
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

# 中央網信辦聯合闢謠平台官方開放資料端點
CN_PIYAO_API_ENDPOINT = "https://www.piyao.org.cn/api/v1/rumor-alerts.json"
PROJECT_EPOCH = "2026-01-01T00:00:00.000Z"

class ChinaPiyaoAdapter(BaseSourceAdapter):
    SOURCE_ID = "cn-cac-piyao-rumor-alerts"
    SOURCE_NAME = "China Joint Fact-Checking Platform / CAC (中國互聯網聯合闢謠平台)"
    LICENSE_TYPE = "China Public Open Information (piyao.org.cn)"
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
                # 排除官方與政務網域名
                if domain and not domain.endswith(".gov.cn") and not domain.endswith(".piyao.org.cn") and domain != "gov.cn":
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

        # 1. 官方來源 Identity SDO (中央網信辦闢謠平台)
        piyao_id = f"identity--{deterministic_uuid('CN_CAC_PIYAO_OFFICIAL')}"
        stix_objects.append({
            "type": "identity",
            "spec_version": "2.1",
            "id": piyao_id,
            "created": PROJECT_EPOCH,
            "modified": PROJECT_EPOCH,
            "name": self.SOURCE_NAME,
            "identity_class": "government",
            "sectors": ["government"],
            "contact_information": "https://www.piyao.org.cn"
        })

        raw_payload = None
        max_retries = 2
        req = urllib.request.Request(CN_PIYAO_API_ENDPOINT, headers=headers)
        for attempt in range(1, max_retries + 1):
            try:
                logging.info("正在請求中國聯合闢謠平台 API (嘗試 %d/%d)...", attempt, max_retries)
                with urllib.request.urlopen(req, timeout=30) as response:
                    if response.status == 200:
                        raw_payload = json.loads(response.read().decode("utf-8"))
                        break
            except Exception as e:
                logging.warning("闢謠平台 API 嘗試 %d 失敗: %s", attempt, str(e))
                time.sleep(2)

        if not raw_payload:
            logging.warning("闢謠平台連線逾時，跳過即時拉取。")
            return stix_objects

        records = raw_payload.get("data", raw_payload.get("records", []))
        logging.info("中國聯合闢謠平台取得原始公報數: %d", len(records))

        for rec in records:
            title = str(rec.get("title") or rec.get("rumor_title") or "涉詐涉謠預警公報").strip()
            date_str = str(rec.get("date") or rec.get("pub_date") or "").strip()
            content = str(rec.get("content") or rec.get("description") or "")
            target_entity = str(rec.get("impersonated_entity") or "國家機關/持牌金融機構").strip()

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

            # 2. 被冒充實體 Identity SDO
            victim_id = f"identity--{deterministic_uuid(f'CN_IMPERSONATED_{target_entity}')}"
            stix_objects.append({
                "type": "identity",
                "spec_version": "2.1",
                "id": victim_id,
                "created": pub_time,
                "modified": pub_time,
                "name": target_entity,
                "identity_class": "organization",
                "sectors": ["government", "financial-services"]
            })

            # 3. 提取涉詐網域 IoC
            domains = self._extract_domains(f"{title} {content}")
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
            report_seed = f"CN_PIYAO_{clean_date}_{title[:30]}"
            report_id = f"report--{deterministic_uuid(report_seed)}"

            stix_objects.append({
                "type": "report",
                "spec_version": "2.1",
                "id": report_id,
                "created": pub_time,
                "modified": pub_time,
                "name": f"官方闢謠: {title[:40]}",
                "description": content[:300] if content else "中央網信辦舉報中心/聯合闢謠平台正式發布之涉詐闢謠公報。",
                "published": pub_time,
                "confidence": 95,
                "x_veritas_license": self.LICENSE_TYPE,
                "external_references": [{
                    "source_name": "中國互聯網聯合闢謠平台",
                    "url": "https://www.piyao.org.cn"
                }],
                "object_refs": [piyao_id, victim_id] + indicator_ids
            })

        return stix_objects
