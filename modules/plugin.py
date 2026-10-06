"""
Plugin Manager — auto-discover & load custom modules from modules/custom/.

Drop any .py file with a class that has:  async def run(self, state) -> List[Dict]
"""
import asyncio
import importlib
import inspect
import os


class PluginManager:
    """Singleton: discovers and caches custom plugins."""

    _instance = None
    _plugins: list = []

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def discover(self, plugin_dir: str = None) -> list:
        """Scan modules/custom/ for plugin classes. Returns cached if already loaded."""
        if self._plugins:
            return self._plugins

        if plugin_dir is None:
            plugin_dir = os.path.join(os.path.dirname(__file__), "custom")

        if not os.path.isdir(plugin_dir):
            return []

        loaded = []
        for fname in sorted(os.listdir(plugin_dir)):
            if fname.startswith("_") or not fname.endswith(".py"):
                continue

            modname = fname[:-3]
            try:
                mod = importlib.import_module(f"modules.custom.{modname}")
                # Find classes with async run(state) method
                for name, obj in inspect.getmembers(mod, inspect.isclass):
                    if name.startswith("_"):
                        continue
                    if hasattr(obj, "run") and inspect.iscoroutinefunction(obj.run):
                        instance = obj()
                        loaded.append(instance)
            except Exception as e:
                from core.ui import w
                w(f"Plugin load failed: {modname} — {e}")

        # Sort by priority (lower = first)
        loaded.sort(key=lambda p: getattr(p, "priority", 100))
        self._plugins = loaded
        return loaded

    def reload(self):
        """Force re-discovery on next call."""
        self._plugins = []

    @property
    def count(self) -> int:
        return len(self._plugins)


# Integration helper

async def run_plugins(state) -> list[dict]:
    """Execute all custom plugins against the current scan state.
    
    Each plugin receives the full PoisonState and returns findings.
    Plugins run SEQUENTIALLY (not parallel) to avoid overwhelming targets.
    """
    from core.ui import ph, i, G, N

    pm = PluginManager()
    plugins = pm.discover()
    if not plugins:
        return []

    ph("CUSTOM PLUGINS: User Extensions")
    all_findings = []

    for plugin in plugins:
        name = getattr(plugin, "name", plugin.__class__.__name__)
        try:
            i(f"Running: {G}{name}{N}")
            findings = await plugin.run(state)
            if findings:
                all_findings.extend(findings)
        except Exception as e:
            from core.ui import w
            w(f"Plugin '{name}' error: {e}")

    return all_findings
