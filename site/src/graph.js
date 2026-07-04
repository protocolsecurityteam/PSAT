import { claimSummaryLine } from "./claimsVocab.js";

// Chip/meta line for a function: registry claim sentences + provenance tier
// when claims are present, else the legacy effect_labels strings (stale rows).
export function functionEffectLine(entry) {
  const claims = claimSummaryLine(entry);
  if (claims) return claims.label;
  return (entry?.effect_labels || []).join(" · ");
}

export function shortenAddress(value) {
  if (!value || typeof value !== "string" || !value.startsWith("0x") || value.length < 12) {
    return value || "Unknown";
  }
  return `${value.slice(0, 6)}...${value.slice(-4)}`;
}

function isZeroAddress(value) {
  return String(value || "").toLowerCase() === "0x0000000000000000000000000000000000000000";
}

export function simplifyDisplayName(name, contractName) {
  const raw = String(name || "").trim();
  if (!raw) {
    return "Unknown";
  }
  const prefix = String(contractName || "").trim();
  if (prefix && raw.toLowerCase().startsWith(`${prefix.toLowerCase()} `)) {
    return raw.slice(prefix.length + 1);
  }
  return raw;
}

export function prettyFunctionName(signature) {
  const raw = String(signature || "");
  const open = raw.indexOf("(");
  if (open === -1) {
    return raw || "function";
  }
  const name = raw.slice(0, open);
  const args = raw.slice(open + 1, -1);
  if (!args) {
    return `${name}()`;
  }
  if (args.includes("[]")) {
    return `${name}(batch)`;
  }
  return `${name}(...)`;
}

function principalByAddress(detail) {
  const principals = detail?.principal_labels?.principals || [];
  return new Map(principals.map((principal) => [String(principal.address || "").toLowerCase(), principal]));
}

function resolvedGraphIndexes(detail) {
  const graph = detail?.resolved_control_graph || {};
  const nodeById = new Map();
  const nodeByAddress = new Map();
  const outgoingById = new Map();

  for (const node of graph.nodes || []) {
    nodeById.set(node.id, node);
    if (node.address) {
      nodeByAddress.set(String(node.address).toLowerCase(), node);
    }
  }

  for (const edge of graph.edges || []) {
    const list = outgoingById.get(edge.from_id) || [];
    list.push(edge);
    outgoingById.set(edge.from_id, list);
  }

  return { nodeById, nodeByAddress, outgoingById };
}

function titleize(value) {
  return String(value || "")
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/_/g, " ")
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

function principalOwnershipSummary(address, resolvedGraph) {
  const node = resolvedGraph.nodeByAddress.get(String(address || "").toLowerCase());
  if (!node) {
    return "";
  }
  const outgoing = resolvedGraph.outgoingById.get(node.id) || [];
  const controllerEdge = outgoing.find((edge) => edge.relation === "controller_value");
  if (!controllerEdge) {
    return "";
  }
  const controllerNode = resolvedGraph.nodeById.get(controllerEdge.to_id);
  if (!controllerNode || isZeroAddress(controllerNode.address)) {
    return "";
  }
  const relation = titleize(controllerEdge.label || "controller");
  if (controllerNode.resolved_type === "safe") {
    const threshold = controllerNode.details?.threshold || "?";
    const signerCount = (controllerNode.details?.owners || []).length || "?";
    return `${relation} Safe ${threshold} / ${signerCount}`;
  }
  return `${relation} ${shortenAddress(controllerNode.address || "")}`;
}

function graphResolvedMeta(node) {
  if (!node) {
    return "UNKNOWN";
  }
  if (node.resolved_type === "safe") {
    return `Safe ${node.details?.threshold || "?"} / ${(node.details?.owners || []).length || "?"}`;
  }
  if (node.resolved_type === "zero") {
    return "ZERO";
  }
  if (node.resolved_type === "contract" && node.contract_name) {
    return "CONTRACT";
  }
  return String(node.resolved_type || "unknown").toUpperCase();
}

function graphResolvedTitle(node) {
  if (!node) {
    return "Unknown";
  }
  if (node.resolved_type === "zero") {
    return "Zero address";
  }
  return node.contract_name || titleize(node.label || node.resolved_type || "principal");
}

function graphPrincipalNodeContent(address, principal, fallbackResolvedType, contractName, resolvedGraph) {
  const normalized = String(address || "").toLowerCase();
  const graphNode = resolvedGraph.nodeByAddress.get(normalized);
  const resolvedType = principal?.resolved_type || fallbackResolvedType || graphNode?.resolved_type || "unknown";
  const roleLabel = simplifyDisplayName(principal?.display_name || "Principal", contractName);
  const ownershipMeta = principalOwnershipSummary(normalized, resolvedGraph);
  const safeMeta =
    principal?.details?.threshold != null
      ? `Safe ${principal.details.threshold} / ${(principal.details.owners || []).length || "?"}`
      : "";

  if (resolvedType === "contract" && graphNode?.contract_name) {
    return {
      title: graphNode.contract_name,
      subtitle: roleLabel,
      meta: ownershipMeta || shortenAddress(normalized),
      resolvedType,
      detailTitle: graphNode.contract_name,
      address: normalized,
      sourceGraphNode: graphNode,
    };
  }

  return {
    title: roleLabel,
    subtitle: shortenAddress(normalized),
    meta: safeMeta || ownershipMeta || String(resolvedType).toUpperCase(),
    resolvedType,
    detailTitle: principal?.display_name || graphNode?.contract_name || "Principal",
    address: normalized,
    sourceGraphNode: graphNode,
  };
}

function upstreamColumn(depth) {
  if (depth <= 1) {
    return "upstream1";
  }
  if (depth === 2) {
    return "upstream2";
  }
  if (depth === 3) {
    return "upstream3";
  }
  return "upstream4";
}

export const PRINCIPAL_COLUMNS = new Set(["principal", "upstream1", "upstream2", "upstream3", "upstream4"]);
export const ADDRESS_GRAPH_COLUMNS = ["upstream4", "upstream3", "upstream2", "upstream1", "contract"];

function addressNodeContent(node, principal) {
  const normalized = String(node?.address || "").toLowerCase();
  const resolvedType = principal?.resolved_type || node?.resolved_type || "unknown";
  const controllerLabel = titleize(node?.details?.controller_label || "");
  const principalName = String(principal?.display_name || "").trim();

  let title = graphResolvedTitle(node);
  if (node?.contract_name) {
    title = node.contract_name;
  } else if (resolvedType === "safe" && controllerLabel) {
    title = controllerLabel;
  } else if (principalName && !["Safe", "Safe signer", "Externally owned account"].includes(principalName)) {
    title = principalName;
  }

  let meta = graphResolvedMeta(node);
  if (resolvedType === "safe") {
    const threshold = principal?.details?.threshold ?? node?.details?.threshold ?? "?";
    const owners = principal?.details?.owners || node?.details?.owners || [];
    meta = `Safe ${threshold} / ${owners.length || "?"}`;
  } else if (resolvedType === "contract" && node?.details?.authority_kind) {
    meta = titleize(String(node.details.authority_kind).replace(/_like$/i, ""));
  }

  return {
    title,
    subtitle: shortenAddress(normalized),
    meta,
    resolvedType,
    detailTitle: principal?.display_name || node?.contract_name || title,
    raw: principal || node,
    graphNode: node,
  };
}

function addressEdgeLabel(edge, toNode) {
  if (edge.relation === "role_principal" && toNode?.details?.controller_label) {
    return titleize(toNode.details.controller_label);
  }
  return titleize(edge.label || edge.relation || "relation");
}

export function buildVisualPermissionGraph(detail) {
  const permissions = detail?.effective_permissions;
  if (!permissions?.functions?.length) {
    return null;
  }

  const principalIndex = principalByAddress(detail);
  const resolvedGraph = resolvedGraphIndexes(detail);
  const nodes = [];
  const edges = [];
  const seenNodes = new Set();
  const seenEdges = new Set();
  const nodeLookup = new Map();
  const roleStats = new Map();

  function addNode(node) {
    if (seenNodes.has(node.id)) {
      return;
    }
    seenNodes.add(node.id);
    nodes.push(node);
    nodeLookup.set(node.id, node);
  }

  function addEdge(edge) {
    const key = `${edge.from}|${edge.to}|${edge.label}`;
    if (seenEdges.has(key)) {
      return;
    }
    seenEdges.add(key);
    edges.push(edge);
  }

  addNode({
    id: "contract:root",
    column: "contract",
    title: permissions.contract_name || "Contract",
    subtitle: shortenAddress(permissions.contract_address),
    meta: permissions.authority_contract ? `Authority ${shortenAddress(permissions.authority_contract)}` : "No authority",
    kind: "contract",
    raw: detail?.contract_analysis?.subject || null,
  });

  function addUpstreamChain(address, childNodeId, maxDepth = 4) {
    const visited = new Set();

    function walk(currentAddress, depth, downstreamNodeId) {
      if (depth > maxDepth) {
        return;
      }
      const currentNode = resolvedGraph.nodeByAddress.get(String(currentAddress || "").toLowerCase());
      if (!currentNode) {
        return;
      }
      const outgoing = (resolvedGraph.outgoingById.get(currentNode.id) || []).filter((edge) =>
        ["controller_value", "safe_owner", "timelock_owner", "proxy_admin_owner", "role_principal"].includes(
          edge.relation,
        ),
      );
      for (const edge of outgoing) {
        const upstreamNode = resolvedGraph.nodeById.get(edge.to_id);
        if (!upstreamNode?.address) {
          continue;
        }
        const upstreamAddress = String(upstreamNode.address).toLowerCase();
        const upstreamPrincipal = principalIndex.get(upstreamAddress);
        if (isZeroAddress(upstreamAddress) || upstreamNode.resolved_type === "zero") {
          continue;
        }
        const visitKey = `${currentNode.id}:${upstreamNode.id}:${edge.relation}`;
        if (visited.has(visitKey)) {
          continue;
        }
        visited.add(visitKey);

        const nodeId = `upstream:${depth}:${upstreamAddress}`;
        const column = upstreamColumn(depth);
        addNode({
          id: nodeId,
          column,
          title: upstreamPrincipal?.display_name || graphResolvedTitle(upstreamNode),
          subtitle: shortenAddress(upstreamAddress),
          meta:
            upstreamPrincipal?.details?.threshold != null
              ? `Safe ${upstreamPrincipal.details.threshold} / ${(upstreamPrincipal.details.owners || []).length || "?"}`
              : graphResolvedMeta(upstreamNode),
          kind: "principal",
          resolvedType: upstreamPrincipal?.resolved_type || upstreamNode.resolved_type || "unknown",
          detailTitle: upstreamPrincipal?.display_name || graphResolvedTitle(upstreamNode),
          raw: upstreamPrincipal || upstreamNode,
        });
        addEdge({ from: nodeId, to: downstreamNodeId, label: edge.label || titleize(edge.relation), raw: edge });
        walk(upstreamAddress, depth + 1, nodeId);
      }
    }

    walk(address, 1, childNodeId);
  }

  for (const entry of permissions.functions) {
    const functionId = `function:${entry.selector}`;
    addNode({
      id: functionId,
      column: "function",
      title: prettyFunctionName(entry.function),
      subtitle: entry.action_summary || "",
      meta: functionEffectLine(entry) || "permissioned function",
      kind: "function",
      detailTitle: entry.function,
      raw: entry,
    });
    addEdge({ from: functionId, to: "contract:root", label: "belongs to" });

    if (entry.authority_public) {
      addNode({
        id: "controller:public",
        column: "controller",
        title: "Public",
        subtitle: "Open capability",
        meta: "Anyone can call",
        kind: "controller",
        raw: { authority_public: true },
      });
      addEdge({ from: "controller:public", to: functionId, label: "can call" });
    }

    for (const controllerGrant of entry.controllers || []) {
      const grantId = `controller:grant:${controllerGrant.controller_id}`;
      const grantPrincipals = controllerGrant.principals || [];
      addNode({
        id: grantId,
        column: "controller",
        title: titleize(controllerGrant.label || controllerGrant.source || "controller"),
        subtitle: "Direct controller",
        meta: grantPrincipals.length
          ? `${grantPrincipals.length} principal${grantPrincipals.length === 1 ? "" : "s"}`
          : titleize(controllerGrant.kind || "controller"),
        kind: "controller",
        raw: controllerGrant,
      });
      addEdge({ from: grantId, to: functionId, label: "can call" });

      for (const principalRef of grantPrincipals) {
        const address = String(principalRef.address || "").toLowerCase();
        if (!address) {
          continue;
        }
        const principal = principalIndex.get(address);
        const principalNode = graphPrincipalNodeContent(
          address,
          principal,
          principalRef.resolved_type,
          permissions.contract_name,
          resolvedGraph,
        );
        addNode({
          id: `principal:${address}`,
          column: "principal",
          title: principalNode.title,
          subtitle: principalNode.subtitle,
          meta: principalNode.meta,
          kind: "principal",
          resolvedType: principalNode.resolvedType,
          detailTitle: principalNode.detailTitle,
          raw: principal || principalRef || principalNode.sourceGraphNode,
          graphNode: principalNode.sourceGraphNode || null,
        });
        addEdge({ from: `principal:${address}`, to: grantId, label: "controls" });
        addUpstreamChain(address, `principal:${address}`);
      }
    }

    if (entry.direct_owner?.address) {
      const ownerAddress = String(entry.direct_owner.address).toLowerCase();
      const ownerPrincipal = principalIndex.get(ownerAddress);
      const ownerNode = graphPrincipalNodeContent(
        ownerAddress,
        ownerPrincipal,
        entry.direct_owner.resolved_type,
        permissions.contract_name,
        resolvedGraph,
      );
      addNode({
        id: `principal:${ownerAddress}`,
        column: "principal",
        title: ownerNode.title,
        subtitle: ownerNode.subtitle,
        meta: ownerNode.meta,
        kind: "principal",
        resolvedType: ownerNode.resolvedType,
        detailTitle: ownerNode.detailTitle,
        raw: ownerPrincipal || entry.direct_owner || ownerNode.sourceGraphNode,
        graphNode: ownerNode.sourceGraphNode || null,
      });
      addNode({
        id: "controller:owner",
        column: "controller",
        title: "Owner",
        subtitle: "Direct gate",
        meta: "Owner check",
        kind: "controller",
        raw: { controller: "owner" },
      });
      addEdge({ from: `principal:${ownerAddress}`, to: "controller:owner", label: "controls" });
      addEdge({ from: "controller:owner", to: functionId, label: "can call" });
      addUpstreamChain(ownerAddress, `principal:${ownerAddress}`);
    }

    for (const roleGrant of entry.authority_roles || []) {
      const roleId = `controller:role:${roleGrant.role}`;
      addNode({
        id: roleId,
        column: "controller",
        title: `Role ${roleGrant.role}`,
        subtitle: "Authority gate",
        meta: "Policy capability",
        kind: "controller",
        raw: roleGrant,
      });
      const stats = roleStats.get(roleId) || { functions: new Set(), principals: new Set() };
      stats.functions.add(prettyFunctionName(entry.function));
      addEdge({ from: roleId, to: functionId, label: "can call" });

      for (const principalRef of roleGrant.principals || []) {
        const address = String(principalRef.address || "").toLowerCase();
        const principal = principalIndex.get(address);
        const principalNode = graphPrincipalNodeContent(
          address,
          principal,
          principalRef.resolved_type,
          permissions.contract_name,
          resolvedGraph,
        );
        addNode({
          id: `principal:${address}`,
          column: "principal",
          title: principalNode.title,
          subtitle: principalNode.subtitle,
          meta: principalNode.meta,
          kind: "principal",
          resolvedType: principalNode.resolvedType,
          detailTitle: principalNode.detailTitle,
          raw: principal || principalRef || principalNode.sourceGraphNode,
          graphNode: principalNode.sourceGraphNode || null,
        });
        stats.principals.add(address);
        addEdge({ from: `principal:${address}`, to: roleId, label: "holds" });
        addUpstreamChain(address, `principal:${address}`);
      }
      roleStats.set(roleId, stats);
    }
  }

  for (const [roleId, stats] of roleStats.entries()) {
    const node = nodeLookup.get(roleId);
    if (!node) {
      continue;
    }
    const fnNames = Array.from(stats.functions);
    node.subtitle = fnNames.length === 1 ? fnNames[0] : `${fnNames[0]} +${fnNames.length - 1}`;
    node.meta = `${stats.principals.size} principal${stats.principals.size === 1 ? "" : "s"}`;
  }

  return { nodes, edges };
}

export function buildVisualAddressGraph(detail) {
  const graph = detail?.resolved_control_graph;
  if (!graph?.nodes?.length) {
    return null;
  }

  const principalIndex = principalByAddress(detail);
  const nodes = [];
  const edges = [];
  const seenNodes = new Set();
  const seenEdges = new Set();

  function addNode(node) {
    if (seenNodes.has(node.id)) {
      return;
    }
    seenNodes.add(node.id);
    nodes.push(node);
  }

  function addEdge(edge) {
    const key = `${edge.from}|${edge.to}|${edge.label}`;
    if (seenEdges.has(key)) {
      return;
    }
    seenEdges.add(key);
    edges.push(edge);
  }

  for (const node of graph.nodes || []) {
    const address = String(node.address || "").toLowerCase();
    if (!address || isZeroAddress(address)) {
      continue;
    }
    const principal = principalIndex.get(address);
    const content = addressNodeContent(node, principal);
    addNode({
      id: node.id,
      column: node.depth === 0 ? "contract" : upstreamColumn(Math.min(Number(node.depth) || 1, 4)),
      title: content.title,
      subtitle: content.subtitle,
      meta: content.meta,
      kind: node.depth === 0 ? "contract" : "principal",
      resolvedType: content.resolvedType,
      detailTitle: content.detailTitle,
      raw: content.raw,
      graphNode: content.graphNode || null,
    });
  }

  const nodeById = new Map((graph.nodes || []).map((node) => [node.id, node]));
  for (const edge of graph.edges || []) {
    const fromNode = nodeById.get(edge.from_id);
    const toNode = nodeById.get(edge.to_id);
    if (!fromNode?.address || !toNode?.address) {
      continue;
    }
    if (isZeroAddress(fromNode.address) || isZeroAddress(toNode.address)) {
      continue;
    }
    addEdge({
      from: edge.from_id,
      to: edge.to_id,
      label: addressEdgeLabel(edge, toNode),
      raw: edge,
    });
  }

  return { nodes, edges };
}

function nodeVisual(node) {
  if (
    node.column === "principal" ||
    node.column === "upstream1" ||
    node.column === "upstream2" ||
    node.column === "upstream3" ||
    node.column === "upstream4"
  ) {
    if (node.resolvedType === "safe") {
      return {
        shape: "square",
        width: 232,
        height: 176,
        fill: "#dcfce7",
        stroke: "#16a34a",
        text: "#14532d",
      };
    }
    if (node.resolvedType === "contract" || node.resolvedType === "timelock" || node.resolvedType === "proxy_admin") {
      return {
        shape: "square",
        width: 232,
        height: 176,
        fill: "#e2e8f0",
        stroke: "#64748b",
        text: "#1e293b",
      };
    }
    if (node.resolvedType === "eoa" || node.resolvedType === "zero") {
      return {
        shape: "circle",
        width: 176,
        height: 176,
        fill: "#bbf7d0",
        stroke: "#16a34a",
        text: "#14532d",
      };
    }
    return {
      shape: "circle",
      width: 176,
      height: 176,
      fill: "#e2e8f0",
      stroke: "#64748b",
      text: "#1e293b",
    };
  }

  if (node.column === "controller") {
    return {
      shape: "rect",
      width: 288,
      height: 120,
      fill: "#fff7ed",
      stroke: "#d97706",
      text: "#7c2d12",
    };
  }

  if (node.column === "function") {
    return {
      shape: "rect",
      width: 420,
      height: 172,
      fill: "#fffbeb",
      stroke: "#b45309",
      text: "#451a03",
    };
  }

  return {
    shape: "rect",
    width: 360,
    height: 176,
    fill: "#ecfeff",
    stroke: "#0f766e",
    text: "#134e4a",
  };
}

function layoutVisualGraph(graph, columns) {
  const grouped = new Map(columns.map((column) => [column, []]));
  for (const node of graph.nodes) {
    grouped.get(node.column)?.push(node);
  }

  const marginX = 72;
  const stageWidth = 3660;
  const baseSpacingY = 218;
  const stageHeight = Math.max(...columns.map((column) => grouped.get(column)?.length || 0), 1) * baseSpacingY + 240;

  const xOffsets = {
    upstream4: marginX,
    upstream3: marginX + 300,
    upstream2: marginX + 600,
    upstream1: marginX + 900,
    principal: marginX + 1220,
    controller: marginX + 1560,
    function: marginX + 1940,
    contract: marginX + 2420,
  };

  const positioned = new Map();
  for (const column of columns) {
    const items = grouped.get(column) || [];
    const totalHeight =
      items.reduce((sum, node) => sum + nodeVisual(node).height, 0) + Math.max(items.length - 1, 0) * 46;
    const startY = column === "contract" ? stageHeight / 2 : Math.max(92, (stageHeight - totalHeight) / 2);
    let currentY = startY;
    items.forEach((node) => {
      const visual = nodeVisual(node);
      const y = column === "contract" ? startY - visual.height / 2 : currentY;
      positioned.set(node.id, {
        ...node,
        x: xOffsets[column],
        y,
        ...visual,
      });
      currentY += visual.height + (column === "contract" ? 0 : 46);
    });
  }

  return {
    width: stageWidth,
    height: stageHeight,
    columns,
    nodes: Array.from(positioned.values()),
    edges: graph.edges.map((edge) => ({
      ...edge,
      from: positioned.get(edge.from),
      to: positioned.get(edge.to),
    })),
  };
}

export function layoutVisualPermissionGraph(graph) {
  return layoutVisualGraph(graph, ["upstream4", "upstream3", "upstream2", "upstream1", "principal", "controller", "function", "contract"]);
}

export function layoutVisualAddressGraph(graph) {
  return layoutVisualGraph(graph, ADDRESS_GRAPH_COLUMNS);
}

function nodeVariant(node) {
  if (
    node.column === "principal" ||
    node.column === "upstream1" ||
    node.column === "upstream2" ||
    node.column === "upstream3" ||
    node.column === "upstream4"
  ) {
    if (node.resolvedType === "safe") {
      return "safe";
    }
    if (node.resolvedType === "contract" || node.resolvedType === "timelock" || node.resolvedType === "proxy_admin") {
      return "contract";
    }
    if (node.resolvedType === "eoa") {
      return "eoa";
    }
    if (node.resolvedType === "zero") {
      return "zero";
    }
    return "principal";
  }
  if (node.column === "controller") {
    return "controller";
  }
  if (node.column === "function") {
    return "function";
  }
  return "root-contract";
}

function slotOffsets(count) {
  if (count <= 0) {
    return [];
  }
  if (count === 1) {
    return [50];
  }
  const start = 18;
  const end = 82;
  const step = (end - start) / (count - 1);
  return Array.from({ length: count }, (_, index) => start + step * index);
}

export function buildReactFlowPermissionGraph(detail) {
  const visualGraph = buildVisualPermissionGraph(detail);
  if (!visualGraph) {
    return null;
  }

  const laidOut = layoutVisualPermissionGraph(visualGraph);
  const visibleEdges = laidOut.edges.filter((edge) => edge.from && edge.to);
  const outgoingByNode = new Map();
  const incomingByNode = new Map();

  for (const edge of visibleEdges) {
    const outgoing = outgoingByNode.get(edge.from.id) || [];
    outgoing.push(edge);
    outgoingByNode.set(edge.from.id, outgoing);

    const incoming = incomingByNode.get(edge.to.id) || [];
    incoming.push(edge);
    incomingByNode.set(edge.to.id, incoming);
  }

  const nodes = laidOut.nodes.map((node) => {
    const outgoing = outgoingByNode.get(node.id) || [];
    const incoming = incomingByNode.get(node.id) || [];
    return {
      id: node.id,
      type: "permissionNode",
      position: { x: node.x, y: node.y },
      draggable: false,
      selectable: true,
      data: {
        title: node.title,
        subtitle: node.subtitle,
        meta: node.meta,
        kind: node.kind,
        variant: nodeVariant(node),
        sourceHandles: slotOffsets(outgoing.length).map((top, index) => ({ id: `source-${index}`, top })),
        targetHandles: slotOffsets(incoming.length).map((top, index) => ({ id: `target-${index}`, top })),
      },
      rawNode: node,
      style: {
        width: node.width,
        height: node.height,
      },
    };
  });

  const edges = visibleEdges.map((edge, index) => {
    const sourceIndex = (outgoingByNode.get(edge.from.id) || []).findIndex((item) => item === edge);
    const targetIndex = (incomingByNode.get(edge.to.id) || []).findIndex((item) => item === edge);
    return {
      id: `${edge.from.id}-${edge.to.id}-${index}`,
      source: edge.from.id,
      target: edge.to.id,
      sourceHandle: sourceIndex >= 0 ? `source-${sourceIndex}` : undefined,
      targetHandle: targetIndex >= 0 ? `target-${targetIndex}` : undefined,
      label: "",
      animated: false,
      selectable: false,
      focusable: false,
      type: "smoothstep",
      className: "rf-edge",
      markerEnd: {
        type: "arrowclosed",
        width: 18,
        height: 18,
        color: "rgba(34, 29, 23, 0.24)",
      },
      data: edge,
    };
  });

  return { width: laidOut.width, height: laidOut.height, nodes, edges };
}

export function wrapText(value, maxChars, maxLines) {
  const text = String(value || "").trim();
  if (!text) {
    return [];
  }

  const words = text.split(/\s+/);
  const lines = [];
  let current = "";

  function pushCurrent() {
    if (current) {
      lines.push(current);
      current = "";
    }
  }

  for (const word of words) {
    if (word.length > maxChars) {
      pushCurrent();
      let remaining = word;
      while (remaining.length > maxChars) {
        lines.push(`${remaining.slice(0, maxChars - 1)}-`);
        remaining = remaining.slice(maxChars - 1);
        if (lines.length >= maxLines) {
          lines[maxLines - 1] = `${lines[maxLines - 1].slice(0, maxChars - 1)}…`;
          return lines.slice(0, maxLines);
        }
      }
      current = remaining;
      continue;
    }

    const candidate = current ? `${current} ${word}` : word;
    if (candidate.length <= maxChars) {
      current = candidate;
      continue;
    }

    pushCurrent();
    current = word;
    if (lines.length >= maxLines) {
      break;
    }
  }

  pushCurrent();
  if (lines.length > maxLines) {
    return [...lines.slice(0, maxLines - 1), `${lines[maxLines - 1].slice(0, maxChars - 1)}…`];
  }
  return lines;
}

export function svgNodeMarkup(node) {
  const titleLines = wrapText(node.title, node.shape === "rect" ? 26 : 16, node.shape === "rect" ? 2 : 3);
  const subtitleLines = wrapText(node.subtitle, node.shape === "rect" ? 34 : 16, node.shape === "rect" ? 3 : 2);
  const metaLines = wrapText(node.meta, node.shape === "rect" ? 34 : 16, 2);

  function block(lines, className, startY = 0) {
    return lines
      .map(
        (line, index) =>
          `<text class="${className}" x="0" y="${startY + index * 16}" text-anchor="middle">${escapeHtml(line)}</text>`,
      )
      .join("");
  }

  const centerX = node.width / 2;
  const centerY = node.height / 2;
  const titleStartY = node.shape === "rect" ? 30 : centerY - 26;
  const subtitleStartY = titleStartY + titleLines.length * 16 + 12;
  const metaStartY = subtitleStartY + subtitleLines.length * 16 + 16;

  const body =
    node.shape === "circle"
      ? `<ellipse cx="${centerX}" cy="${centerY}" rx="${node.width / 2}" ry="${node.height / 2}" />`
      : `<rect x="0" y="0" width="${node.width}" height="${node.height}" rx="18" ry="18" />`;

  return `
    <g class="graph-svg-node ${escapeHtml(node.kind)}" transform="translate(${node.x}, ${node.y})" data-node-id="${escapeHtml(
      node.id,
    )}">
      <g class="graph-svg-shape" fill="${node.fill}" stroke="${node.stroke}" stroke-width="3">
        ${body}
      </g>
      <g transform="translate(${centerX}, ${titleStartY})" fill="${node.text}">
        ${block(titleLines, "graph-svg-title")}
        ${block(subtitleLines, "graph-svg-subtitle", subtitleLines.length ? subtitleStartY - titleStartY : 0)}
        ${block(metaLines, "graph-svg-meta", metaLines.length ? metaStartY - titleStartY : 0)}
      </g>
    </g>
  `;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}
