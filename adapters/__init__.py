"""
自動反射發現 adapters/ 目錄下所有可用的 BaseSourceAdapter 子類別。
新增適配器只要放入目錄即自動生效，完全無需修改主程式。
"""
import importlib
import inspect
import pkgutil
from typing import List, Type
from .base import BaseSourceAdapter

def discover_adapters() -> List[Type[BaseSourceAdapter]]:
    adapters = []
    for _, module_name, _ in pkgutil.iter_modules(__path__):
        if module_name == "base":
            continue
        full_module_name = f"{__name__}.{module_name}"
        module = importlib.import_module(full_module_name)
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if issubclass(obj, BaseSourceAdapter) and obj is not BaseSourceAdapter:
                if getattr(obj, "IS_ACTIVE", True):
                    adapters.append(obj)
    return adapters
