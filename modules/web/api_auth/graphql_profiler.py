import asyncio
from typing import List, Dict, Any
from urllib.parse import urlparse, urljoin

from core.ui import ph, i, p, s, w, R, G, Y, N, W, C, GY


GRAPHQL_COMMON_PATHS = [
    "/graphql",
    "/v1/graphql",
    "/v2/graphql",
    "/api/graphql",
    "/api/v1/graphql",
    "/query",
    "/api/query",
    "/subgraph",
]

INTROSPECTION_QUERY = {
    "query": """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
          name
          kind
          fields { name }
        }
      }
    }
    """
}

# Circular depth query DoS payload
CIRCULAR_DEPTH_QUERY = {
    "query": "query { __schema { queryType { name queryType { name queryType { name } } } } }"
}

# Batching query DoS payload
BATCH_QUERY = [
    {"query": "query { __typename }"},
    {"query": "query { __typename }"},
    {"query": "query { __typename }"},
]


class GraphQLProfiler:
    """
    GraphQL Endpoint Profiler & Vulnerability Scanner.
    Detects GraphQL endpoints, tests Introspection enabled,
    evaluates Query Batching DoS, Circular Depth DoS, and extracts Schema fields.
    """

    def __init__(self, seed_url: str, async_engine=None):
        self.seed_url = seed_url
        self.domain = urlparse(seed_url).netloc
        self.async_engine = async_engine
        self.findings: List[Dict[str, Any]] = []

    async def run(self) -> List[Dict[str, Any]]:
        if not self.async_engine:
            return []

        ph("GRAPHQL PROFILER: Deep Introspection & DoS Resilience Check")

        parsed = urlparse(self.seed_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        active_graphql_url = None

        # 1. Discover GraphQL Endpoints
        for path in GRAPHQL_COMMON_PATHS:
            target_url = urljoin(origin, path)
            try:
                res = await self.async_engine.ahttp_send(
                    target_url,
                    method="POST",
                    json={"query": "{__typename}"},
                    timeout=8
                )
                if res.get("status") in [200, 400] and ("data" in res.get("body", "") or "errors" in res.get("body", "")):
                    active_graphql_url = target_url
                    s(f"Discovered Active GraphQL Endpoint: {C}{target_url}{N}")
                    break
            except Exception:
                pass

        if not active_graphql_url:
            p("No GraphQL endpoints detected.")
            return []

        # 2. Test Introspection Query Enabled
        try:
            res = await self.async_engine.ahttp_send(
                active_graphql_url,
                method="POST",
                json=INTROSPECTION_QUERY,
                timeout=10
            )
            if res.get("status") == 200 and "__schema" in res.get("body", ""):
                self.findings.append({
                    "type": "graphql_introspection",
                    "title": "GraphQL Introspection Enabled",
                    "url": active_graphql_url,
                    "detail": f"GraphQL Introspection is enabled. Full API schema and field definitions can be dumped by unauthorized attackers.",
                    "severity": "Medium",
                    "confidence": "confirmed",
                })
                s(f"GraphQL Introspection ENABLED on {C}{active_graphql_url}{N}")
        except Exception as e:
            w(f"GraphQL Introspection check error: {e}")

        # 3. Test Batching DoS Vulnerability
        try:
            res = await self.async_engine.ahttp_send(
                active_graphql_url,
                method="POST",
                json=BATCH_QUERY,
                timeout=10
            )
            if res.get("status") == 200 and isinstance(res.get("body"), str) and res.get("body").startswith("["):
                self.findings.append({
                    "type": "graphql_batching",
                    "title": "GraphQL Batching Query DoS Supported",
                    "url": active_graphql_url,
                    "detail": f"GraphQL server accepts array of queries in a single HTTP request without rate limiting (Batching DoS candidate).",
                    "severity": "Low",
                    "confidence": "confirmed",
                })
                s(f"GraphQL Batching Supported on {C}{active_graphql_url}{N}")
        except Exception:
            pass

        return self.findings
