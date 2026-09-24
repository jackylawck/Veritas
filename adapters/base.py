"""
Veritas Base Adapter Specification
定義所有官方 API 適配器必須履行的契約，提供確定性 STIX UUIDv5 生成器。
"""
from abc import ABC, abstractmethod
from typing import Any, Dict, List
import uuid

# 固定專案命名空間 UUID (DNS Namespace)
NAMESPACE_VERITAS = uuid.UUID("00ab11cd-22ef-3344-5566-778899aabbcc")

def deterministic_uuid(seed: str) -> str:
    """以統一種子字串生成跨時間冪等的 UUIDv5"""
    return str(uuid.uuid5(NAMESPACE_VERITAS, seed))

class BaseSourceAdapter(ABC):
    SOURCE_ID: str = ""
    SOURCE_NAME: str = ""
    LICENSE_TYPE: str = ""
    IS_ACTIVE: bool = True

    @abstractmethod
    def fetch_and_parse(self) -> List[Dict[str, Any]]:
        """
        呼叫官方開放端點，解析為符合 STIX 2.1 規格的 SDO/SCO 物件字典清單。
        若失敗必須拋出 Exception，由外層進行沙盒容錯。
        """
        pass
