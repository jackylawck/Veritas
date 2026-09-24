"""
Veritas Ingestion Engine
1. 自動修復專案根目錄搜尋路徑，防範 ModuleNotFoundError: No module named 'adapters'
2. 動態調度所有適配器，執行沙盒隔離採集。
3. 全域語意級去重合併：created 取最早、modified 取最晚、object_refs 取聯集。
4. 封裝當日全量存證至 archive/ 冷存檔。
5. 滾動過濾：熱端點 bundle-latest.json 滾動保留過去 2 年 (730 天) 資料。
"""
import sys
from pathlib import Path

# 將專案根目錄加入 Python 搜尋路徑
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List
from adapters import discover_adapters
from adapters.base import deterministic_uuid

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

HKMA_AUTHORITY_ID = f"identity--{deterministic_uuid('HKMA_OFFICIAL')}"
ROLLING_DAYS = 730  # 過去 2 年 (730 天)

def deduplicate_stix_objects(objects: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    按 STIX ID 進行語意級去重合併：
    - created 取最早 (earliest)
    - modified 取最晚 (latest)
    - object_refs 合併為排序唯一列表 (union)
    - 其他欄位保留首次出現者
    """
    deduped: Dict[str, Dict[str, Any]] = {}

    for obj in objects:
        oid = obj.get("id")
        if not oid:
            continue

        if oid not in deduped:
            deduped[oid] = dict(obj)
            continue

        existing = deduped[oid]

        # 1. 合併 created (取最早)
        new_created = obj.get("created")
        existing_created = existing.get("created")
        if new_created and existing_created:
            existing["created"] = min(existing_created, new_created)

        # 2. 合併 modified (取最晚)
        new_mod = obj.get("modified")
        existing_mod = existing.get("modified")
        if new_mod and existing_mod:
            existing["modified"] = max(existing_mod, new_mod)

        # 3. 合併 object_refs (聯集去重)
        if "object_refs" in obj:
            merged_refs = set(existing.get("object_refs", [])) | set(obj.get("object_refs", []))
            existing["object_refs"] = sorted(merged_refs)

    return list(deduped.values())

def run():
    adapters = discover_adapters()
    logging.info("動態發現 %d 個可用官方適配器", len(adapters))

    raw_objects = []
    now = datetime.now(timezone.utc)
    today_str = now.strftime("%Y%m%d")
    cutoff_date = now - timedelta(days=ROLLING_DAYS)

    for adapter_cls in adapters:
        adapter = adapter_cls()
        logging.info("啟動適配器: %s", adapter.SOURCE_ID)
        try:
            objects = adapter.fetch_and_parse()
            raw_objects.extend(objects)
            logging.info("  └─ 成功產出 %d 個原始 STIX 物件", len(objects))
        except Exception as e:
            logging.error("  └─ 執行失敗並隔離: %s", str(e), exc_info=True)

    # --- 0. 全域語意級去重合併 ---
    before_count = len(raw_objects)
    all_objects = deduplicate_stix_objects(raw_objects)
    logging.info("全域去重合併完成: %d -> %d 個唯一 STIX 物件", before_count, len(all_objects))

    # --- 1. 冷存檔 (全量歷史快照) ---
    archive_dir = Path(f"public/api/archive/{now.strftime('%Y/%m')}")
    archive_dir.mkdir(parents=True, exist_ok=True)
    archive_file = archive_dir / f"bundle-{today_str}.json"

    daily_snapshot = {
        "type": "bundle",
        "id": f"bundle--{deterministic_uuid('SNAPSHOT_' + today_str)}",
        "objects": all_objects
    }
    with open(archive_file, "w", encoding="utf-8") as f:
        json.dump(daily_snapshot, f, ensure_ascii=False)
    logging.info("冷存檔快照已封裝: %s", archive_file)

    # --- 2. 熱端點 (過去 2 年滾動，若不足則回退保留最新 20 筆避免冷啟動為 0) ---
    all_reports = [obj for obj in all_objects if obj.get("type") == "report"]
    all_reports.sort(key=lambda x: x.get("published", ""), reverse=True)

    recent_reports = [
        r for r in all_reports
        if datetime.fromisoformat(r["published"].replace("Z", "+00:00")) >= cutoff_date
    ]

    # 回退保護機制：若過去 2 年內無資料，取全量歷史最新 20 筆作為 Baseline
    if len(recent_reports) == 0 and len(all_reports) > 0:
        logging.info("指定窗口內無新公報，回退載入歷史最新 %d 筆", min(20, len(all_reports)))
        recent_reports = all_reports[:20]

    needed_ids = set()
    for r in recent_reports:
        for ref_id in r.get("object_refs", []):
            needed_ids.add(ref_id)

    recent_report_ids = {r["id"] for r in recent_reports}

    hot_objects = [
        obj for obj in all_objects
        if obj.get("id") == HKMA_AUTHORITY_ID
        or obj.get("id") in needed_ids
        or obj.get("id") in recent_report_ids
    ]

    hot_bundle = {
        "type": "bundle",
        "id": f"bundle--{deterministic_uuid('HOT_2Y_' + today_str)}",
        "objects": hot_objects
    }

    latest_file = Path("public/api/bundle-latest.json")
    latest_file.parent.mkdir(parents=True, exist_ok=True)
    with open(latest_file, "w", encoding="utf-8") as f:
        json.dump(hot_bundle, f, ensure_ascii=False)

    logging.info("熱資料端點更新完成: %s (保留 2 年內共 %d 筆物件，含 %d 筆 Report)", latest_file, len(hot_objects), len(recent_reports))

if __name__ == "__main__":
    run()
