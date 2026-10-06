"""Custom plugins directory. Drop .py files here and they auto-load.

Plugin format:
    class MyPlugin:
        name = "My Plugin Name"
        priority = 50  # lower = runs earlier (default: 100)

        async def run(self, state):
            '''state has: target, services, scan_urls, params,
                         async_engine, session_manager, findings,
                         scope_guard, is_turbo, wave, time_left'''
            findings = []
            # ... your custom scan logic ...
            return findings

See _example_jwt.py for a working example.
"""
