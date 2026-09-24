"""
香港證券及期貨事務監察委員會 (SFC) 可疑網站及無牌公司名單適配器
資料來源：香港證監會官方開放數據 (data.gov.hk / sfc.hk)
"""
import csv
import io
import logging
import re
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, List, Set
from .base import BaseSourceAdapter, deterministic_uuid

# 香港政府開放資料平台提供的 SFC 官方警示名單 CSV 鏡像
SFC_CSV_ENDPOINT = "https://www.sfc.hk/-/media/EN/files/ER/Alert-List/alertlist.csv"
PROJECT_EPOCH = "2026-01-01T00:00:00.000Z"

class SFCAlertAdapter(BaseSourceAdapter):
    SOURCE_ID = "hk-sfc-unlicensed-alert-list"
    SOURCE_NAME = "Securities and Futures Commission (香港證券及期貨事務監察委員會)"
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
                if domain and not domain.endswith(".gov.hk") and not domain.endswith(".sfc.hk") and domain != "sfc.hk":
                    domains.add(domain)
            except Exception:
                continue
        return domains

    def fetch_and_parse(self) -> List[Dict[str, Any]]:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }
        stix_objects = []

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

        req = urllib.request.Request(SFC_CSV_ENDPOINT, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                content = resp.read().decode("utf-8-sig", errors="ignore")
                reader = csv.DictReader(io.StringIO(content))
                for row in reader:
                    name = (row.get("Name") or row.get("Entity Name") or "").strip()
                    date_str = (row.get("Date") or row.get("Added Date") or "").strip()
                    web_str = (row.get("Website") or row.get("Websites") or "").strip()
                    if not name:
                        continue

                    try:
                        pub_time = datetime.strptime(date_str, "%d/%m/%Y").replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
                    except Exception:
                        pub_time = PROJECT_EPOCH

                    domains = self._extract_domains(web_str)
                    ind_ids = []
                    for d in domains:
                        ind_id = f"indicator--{deterministic_uuid(f'domain:{d}')}"
                        ind_ids.append(ind_id)
                        stix_objects.append({
                            "type": "indicator",
                            "spec_version": "2.1",
                            "id": ind_id,
                            "created": pub_time,
                            "modified": pub_time,
                            "pattern_type": "stix",
                            "pattern": f"[domain-name:value = '{d}']",
                            "valid_from": pub_time,
                            "confidence": 95
                        })

                    report_id = f"report--{deterministic_uuid(f'SFC_{date_str}_{name}')}"
                    stix_objects.append({
                        "type": "report",
                        "spec_version": "2.1",
                        "id": report_id,
                        "created": pub_time,
                        "modified": pub_time,
                        "name": f"SFC Alert: {name}",
                        "published": pub_time,
                        "confidence": 95,
                        "x_veritas_license": self.LICENSE_TYPE,
                        "object_refs": [sfc_id] + ind_ids
                    })
        except Exception as e:
            logging.warning("SFC 獲取失敗，跳過: %s", str(e))

        return stix_objects
