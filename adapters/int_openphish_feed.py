"""
OpenPhish 國際即時品牌偽冒與網絡釣魚威脅適配器
資料授權：OpenPhish Community Edition License
涵蓋：針對全球金融機構、電信與雲端服務之即時 Brand Impersonation 釣魚網址
"""
import logging
import re
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, List, Set
from .base import BaseSourceAdapter, deterministic_uuid

OPENPHISH_COMMUNITY_FEED = "https://openphish.com/feed.txt"
PROJECT_EPOCH = "2026-01-01T00:00:00.000Z"

class OpenPhishFeedAdapter(BaseSourceAdapter):
    SOURCE_ID = "int-openphish-community-feed"
    SOURCE_NAME = "OpenPhish Threat Intelligence (國際即時防釣魚情報)"
    LICENSE_TYPE = "OpenPhish Community Edition Terms"
    IS_ACTIVE = True

    def _extract_domain(self, raw_url: str) -> str | None:
        try:
            target = raw_url.strip()
            if not target:
                return None
            if not re.match(r'^https?://', target, re.IGNORECASE):
                target = f"http://{target}"
            parsed = urllib.parse.urlparse(target)
            domain = (parsed.hostname or "").lower().strip(".,;:)'\"")
            return domain if domain and "." in domain else None
        except Exception:
            return None

    def fetch_and_parse(self) -> List[Dict[str, Any]]:
        headers = {
            "User-Agent": "Veritas-OSINT-Mirror/1.0 (+https://github.com/jackylawck/Veritas)",
            "Accept": "text/plain"
        }
        stix_objects = []
        now = datetime.now(timezone.utc)
        pub_time = now.isoformat().replace("+00:00", "Z")
        date_str = now.strftime("%Y-%m-%d")

        # 1. 來源 Identity SDO
        openphish_id = f"identity--{deterministic_uuid('OPENPHISH_OFFICIAL')}"
        stix_objects.append({
            "type": "identity",
            "spec_version": "2.1",
            "id": openphish_id,
            "created": PROJECT_EPOCH,
            "modified": PROJECT_EPOCH,
            "name": self.SOURCE_NAME,
            "identity_class": "organization",
            "sectors": ["technology"],
            "contact_information": "https://openphish.com"
        })

        raw_text = None
        max_retries = 2
        req = urllib.request.Request(OPENPHISH_COMMUNITY_FEED, headers=headers)
        for attempt in range(1, max_retries + 1):
            try:
                logging.info("正在請求 OpenPhish Feed (嘗試 %d/%d)...", attempt, max_retries)
                with urllib.request.urlopen(req, timeout=25) as response:
                    if response.status == 200:
                        raw_text = response.read().decode("utf-8", errors="ignore")
                        break
            except Exception as e:
                logging.warning("OpenPhish 連線嘗試 %d 失敗: %s", attempt, str(e))
                time.sleep(2)

        if not raw_text:
            logging.warning("OpenPhish 暫時無法連線，跳過即時拉取。")
            return stix_objects

        lines = [line.strip() for line in raw_text.splitlines() if line.strip() and not line.startswith("#")]
        logging.info("OpenPhish 取得即時釣魚 URL 總數: %d", len(lines))

        # 採集最新 50 筆高危指標，維持 Bundle 輕量且零雜訊
        for url in lines[:50]:
            domain = self._extract_domain(url)
            if not domain:
                continue

            ind_id = f"indicator--{deterministic_uuid(f'domain:{domain}')}"
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

            report_seed = f"OPENPHISH_{date_str}_{domain}"
            report_id = f"report--{deterministic_uuid(report_seed)}"

            stix_objects.append({
                "type": "report",
                "spec_version": "2.1",
                "id": report_id,
                "created": pub_time,
                "modified": pub_time,
                "name": f"OpenPhish Alert: {domain}",
                "description": f"Active credential phishing infrastructure targeting global brands: {url[:60]}",
                "published": pub_time,
                "confidence": 90,
                "x_veritas_license": self.LICENSE_TYPE,
                "external_references": [{
                    "source_name": "OpenPhish Feed",
                    "url": "https://openphish.com"
                }],
                "object_refs": [openphish_id, ind_id]
            })

        return stix_objects
