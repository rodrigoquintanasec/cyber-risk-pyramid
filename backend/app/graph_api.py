"""REST endpoints for the Threat Relationship Graph (read-only, bounded)."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query

from . import db, graph

router = APIRouter(prefix="/api/v1/graph", tags=["graph"])


def _node(v: str) -> str:
    v = (v or "").strip()
    if v.startswith("attack:") or v.startswith("cve:"):
        k, _, rest = v.partition(":")
        v = f"{k}:{rest.upper()}"
    try:
        graph.parse(v)
    except ValueError:
        raise HTTPException(422, "Invalid node id")
    return v


def _csv(v: str | None, allowed: list[str], name: str) -> set[str] | None:
    if not v:
        return None
    items = {x.strip() for x in v.split(",") if x.strip()}
    if not items or not items <= set(allowed):
        raise HTTPException(422, f"Invalid {name}")
    return items


@router.get("/meta")
def graph_meta():
    with db.connect() as con:
        return graph.meta(con)


@router.get("/search")
def graph_search(q: str = Query("", max_length=80), type: str | None = Query(None, max_length=20), limit: int = Query(15, ge=1, le=30)):
    if type and type not in graph.NODE_TYPES:
        raise HTTPException(422, "Invalid entity type")
    with db.connect() as con:
        return {"items": graph.search(con, q, type, limit)}


@router.get("/neighbors")
def graph_neighbors(node: str = Query(..., max_length=200), depth: int = Query(1, ge=1, le=2), rel: str | None = Query(None, max_length=120),
                    node_types: str | None = Query(None, max_length=200), include_candidates: bool = False,
                    limit: int = Query(40, ge=1, le=150), offset: int = Query(0, ge=0, le=5000),
                    max_nodes: int | None = Query(None, ge=5, le=400), max_edges: int | None = Query(None, ge=10, le=1500)):
    nid = _node(node)
    with db.connect() as con:
        res = graph.neighborhood(con, nid, depth=depth, rels=_csv(rel, graph.REL_TYPES, "relation filter"), node_types=_csv(node_types, graph.NODE_TYPES, "node type filter"),
                                 include_candidates=include_candidates, limit=limit, offset=offset, max_nodes=max_nodes, max_edges=max_edges)
    if res is None:
        raise HTTPException(404, "Entity not found")
    return res


@router.get("/node")
def graph_node(id: str = Query(..., max_length=200)):
    with db.connect() as con:
        d = graph.node_detail(con, _node(id))
    if not d:
        raise HTTPException(404, "Entity not found")
    return d


@router.get("/edge")
def graph_edge(id: str = Query(..., max_length=700)):
    try:
        with db.connect() as con:
            d = graph.edge_detail(con, id.strip())
    except ValueError:
        raise HTTPException(422, "Invalid edge id")
    if not d:
        raise HTTPException(404, "Relationship not found")
    return d
