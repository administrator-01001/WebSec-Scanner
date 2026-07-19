import importlib
import inspect
import pkgutil
from typing import Any


class BasePlugin:
    name: str = ""
    description: str = ""
    category: str = ""

    async def run(self, target, http_client) -> list:
        raise NotImplementedError


class PluginRegistry:
    _registry: dict[str, dict[str, type[BasePlugin]]] = {
        "recon": {},
        "vuln": {},
        "cve": {},
        "crawl": {},
    }

    @classmethod
    def register(cls, plugin_class: type[BasePlugin], category: str):
        if category not in cls._registry:
            cls._registry[category] = {}
        cls._registry[category][plugin_class.name] = plugin_class

    @classmethod
    def get_plugin(cls, name: str, category: str) -> type[BasePlugin]:
        return cls._registry.get(category, {}).get(name)

    @classmethod
    def get_all_plugins(cls, category: str) -> dict[str, type[BasePlugin]]:
        return cls._registry.get(category, {})

    @classmethod
    def list_plugins(cls, category: str) -> list[str]:
        return list(cls._registry.get(category, {}).keys())

    @classmethod
    async def run_plugin(cls, name: str, category: str, target, http_client) -> list:
        plugin_cls = cls.get_plugin(name, category)
        if plugin_cls:
            plugin = plugin_cls()
            return await plugin.run(target, http_client)
        return []

    @classmethod
    def discover_plugins(cls):
        category_dirs = {"recon": "recon", "vuln": "vulnerability", "cve": "cve", "crawl": "crawl"}
        for category, dirname in category_dirs.items():
            module_path = f"webscanner.modules.{dirname}"
            try:
                module = importlib.import_module(module_path)
            except ImportError:
                continue

            prefix = f"{module_path}."
            for importer, modname, is_pkg in pkgutil.walk_packages(
                path=module.__path__, prefix=prefix
            ):
                if modname.endswith("base") or modname == module_path or modname.endswith("__init__"):
                    continue
                if modname in ("webscanner.modules.vulnerability.known_vulns",):
                    continue
                try:
                    mod = importlib.import_module(modname)
                    for name, obj in inspect.getmembers(mod, inspect.isclass):
                        if (
                            issubclass(obj, BasePlugin)
                            and obj is not BasePlugin
                            and hasattr(obj, "name")
                            and obj.name
                        ):
                            cls.register(obj, category)
                except Exception:
                    pass


def plugin(name: str, description: str, category: str):
    def decorator(cls):
        cls.name = name
        cls.description = description
        cls.category = category
        return cls

    return decorator
