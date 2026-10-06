import json
import re
import urllib.parse
from typing import Dict, List, Tuple, Any

class OpenAPIParser:
    """
    Ingests OpenAPI / Swagger (v2 & v3) and Postman Collections (v2.0 & v2.1).
    Extracts live endpoints, HTTP methods, path/query/body parameters, and session tokens.
    """

    def __init__(self, base_url: str = ""):
        self.base_url = base_url.rstrip("/")
        self.endpoints: List[str] = []
        self.params: Dict[str, List[str]] = {}
        self.headers: Dict[str, str] = {}

    def parse_spec(self, content: str, spec_url: str = "") -> Dict[str, Any]:
        """Parse JSON or raw string specification content."""
        if not content:
            return {"endpoints": [], "params": {}}

        try:
            data = json.loads(content)
        except Exception:
            return {"endpoints": [], "params": {}}

        if not self.base_url and spec_url:
            parsed = urllib.parse.urlparse(spec_url)
            self.base_url = f"{parsed.scheme}://{parsed.netloc}"

        # Detect Spec Type
        if "swagger" in data or "openapi" in data or "paths" in data:
            self._parse_openapi(data)
        elif "info" in data and ("item" in data or "schema" in str(data.get("info", {}))):
            self._parse_postman(data)

        return {"endpoints": list(set(self.endpoints)), "params": self.params, "headers": self.headers}

    def _parse_openapi(self, data: dict):
        base_path = ""
        if "basePath" in data:
            base_path = data["basePath"].rstrip("/")

        paths = data.get("paths", {})
        for path_str, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue

            # Replace path placeholders e.g. /users/{id} -> /users/1
            clean_path = re.sub(r"\{[^}]+\}", "1", path_str)
            full_url = f"{self.base_url}{base_path}{clean_path}" if self.base_url else clean_path
            self.endpoints.append(full_url)

            param_list = []
            for method, spec in path_item.items():
                if not isinstance(spec, dict):
                    continue

                # Query & Path Parameters
                for p in spec.get("parameters", []):
                    if isinstance(p, dict) and "name" in p:
                        param_list.append(p["name"])

                # Body schema parameters (Swagger 2 & OpenAPI 3)
                request_body = spec.get("requestBody", {})
                if isinstance(request_body, dict):
                    content_map = request_body.get("content", {})
                    for media_type, media_spec in content_map.items():
                        schema = media_spec.get("schema", {})
                        param_list.extend(self._extract_schema_keys(schema))

            if param_list:
                norm_path = urllib.parse.urlparse(full_url).path or "/"
                if norm_path not in self.params:
                    self.params[norm_path] = []
                self.params[norm_path].extend(param_list)
                self.params[norm_path] = list(set(self.params[norm_path]))

    def _parse_postman(self, data: dict):
        items = data.get("item", [])
        self._walk_postman_items(items)

    def _walk_postman_items(self, items: list):
        for item in items:
            if not isinstance(item, dict):
                continue

            if "item" in item and isinstance(item["item"], list):
                self._walk_postman_items(item["item"])
            elif "request" in item:
                req = item["request"]
                if isinstance(req, str):
                    self.endpoints.append(req)
                    continue

                url_obj = req.get("url", {})
                raw_url = ""
                param_list = []

                if isinstance(url_obj, str):
                    raw_url = url_obj
                elif isinstance(url_obj, dict):
                    raw_url = url_obj.get("raw", "")
                    for q in url_obj.get("query", []):
                        if isinstance(q, dict) and "key" in q:
                            param_list.append(q["key"])

                if raw_url:
                    clean_url = re.sub(r"\{\{[^}]+\}\}", "1", raw_url)
                    if self.base_url and not clean_url.startswith("http"):
                        clean_url = f"{self.base_url}/{clean_url.lstrip('/')}"
                    self.endpoints.append(clean_url)

                    # Extract body params
                    body = req.get("body", {})
                    if isinstance(body, dict):
                        mode = body.get("mode")
                        if mode == "raw" and "raw" in body:
                            try:
                                json_body = json.loads(body["raw"])
                                param_list.extend(self._extract_schema_keys(json_body))
                            except Exception:
                                pass
                        elif mode == "formdata":
                            for fd in body.get("formdata", []):
                                if isinstance(fd, dict) and "key" in fd:
                                    param_list.append(fd["key"])

                    norm_path = urllib.parse.urlparse(clean_url).path or "/"
                    if norm_path not in self.params:
                        self.params[norm_path] = []
                    self.params[norm_path].extend(param_list)
                    self.params[norm_path] = list(set(self.params[norm_path]))

    def _extract_schema_keys(self, obj: Any) -> List[str]:
        keys = []
        if isinstance(obj, dict):
            if "properties" in obj and isinstance(obj["properties"], dict):
                keys.extend(obj["properties"].keys())
            else:
                for k, v in obj.items():
                    if k not in ("type", "required", "properties", "items"):
                        keys.append(k)
                    keys.extend(self._extract_schema_keys(v))
        elif isinstance(obj, list):
            for item in obj:
                keys.extend(self._extract_schema_keys(item))
        return keys
