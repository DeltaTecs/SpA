import { useEffect, useMemo, useState } from "react";
import type { KeyboardEvent } from "react";
import type { EndpointNode } from "../../api/types";

interface TreeNodeProps {
  node: EndpointNode;
  nodeId: string;
  depth: number;
  expandedIds: Set<string>;
  onToggle: (nodeId: string) => void;
}

function TreeNode({ node, nodeId, depth, expandedIds, onToggle }: TreeNodeProps) {
  const hasChildren = node.children.length > 0;
  const open = hasChildren && expandedIds.has(nodeId);

  const toggle = () => {
    if (hasChildren) onToggle(nodeId);
  };

  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    if (!hasChildren || (event.key !== "Enter" && event.key !== " ")) return;
    event.preventDefault();
    onToggle(nodeId);
  };

  return (
    <li className="tree__item">
      <div
        className="tree__row"
        style={{ paddingLeft: `${depth * 16}px` }}
        onClick={toggle}
        onKeyDown={onKeyDown}
        role={hasChildren ? "button" : undefined}
        tabIndex={hasChildren ? 0 : undefined}
        aria-expanded={hasChildren ? open : undefined}
      >
        <span className="tree__toggle">
          {hasChildren ? (open ? "v" : ">") : "."}
        </span>
        <span className={`tree__name tree__name--${node.type}`}>{node.name}</span>
        <span className="tree__count">{node.count}</span>
      </div>
      {hasChildren && open && (
        <ul className="tree__children">
          {node.children.map((child, idx) => (
            <TreeNode
              key={treeNodeId(nodeId, child, idx)}
              node={child}
              nodeId={treeNodeId(nodeId, child, idx)}
              depth={depth + 1}
              expandedIds={expandedIds}
              onToggle={onToggle}
            />
          ))}
        </ul>
      )}
    </li>
  );
}

export function TreeView({ nodes }: { nodes: EndpointNode[] }) {
  const expandableIds = useMemo(() => collectExpandableIds(nodes), [nodes]);
  const defaultExpandedIds = useMemo(() => collectDefaultExpandedIds(nodes), [nodes]);
  const [expandedIds, setExpandedIds] = useState(defaultExpandedIds);

  useEffect(() => {
    setExpandedIds(defaultExpandedIds);
  }, [defaultExpandedIds]);

  if (nodes.length === 0) {
    return <div className="tree__empty">No HTTP endpoints recorded.</div>;
  }

  const allExpanded =
    expandableIds.length > 0 &&
    expandableIds.every((nodeId) => expandedIds.has(nodeId));

  const toggleAll = () => {
    setExpandedIds(allExpanded ? new Set() : new Set(expandableIds));
  };

  const toggleNode = (nodeId: string) => {
    setExpandedIds((current) => {
      const next = new Set(current);
      if (next.has(nodeId)) {
        next.delete(nodeId);
      } else {
        next.add(nodeId);
      }
      return next;
    });
  };

  return (
    <>
      <div className="tree-toolbar">
        <button
          className="tree-action"
          type="button"
          onClick={toggleAll}
          disabled={expandableIds.length === 0}
        >
          {allExpanded ? "Collapse all" : "Expand all"}
        </button>
      </div>
      <ul className="tree">
        {nodes.map((node, idx) => (
          <TreeNode
            key={treeNodeId("root", node, idx)}
            node={node}
            nodeId={treeNodeId("root", node, idx)}
            depth={0}
            expandedIds={expandedIds}
            onToggle={toggleNode}
          />
        ))}
      </ul>
    </>
  );
}

function collectExpandableIds(nodes: EndpointNode[], parentId = "root"): string[] {
  return nodes.flatMap((node, idx) => {
    const nodeId = treeNodeId(parentId, node, idx);
    if (node.children.length === 0) return [];
    return [nodeId, ...collectExpandableIds(node.children, nodeId)];
  });
}

function collectDefaultExpandedIds(
  nodes: EndpointNode[],
  parentId = "root",
  depth = 0,
): Set<string> {
  const expandedIds = new Set<string>();

  nodes.forEach((node, idx) => {
    const nodeId = treeNodeId(parentId, node, idx);
    if (node.children.length === 0) return;

    if ((depth === 0 && idx === 0) || depth === 1) {
      expandedIds.add(nodeId);
    }

    for (const childId of collectDefaultExpandedIds(
      node.children,
      nodeId,
      depth + 1,
    )) {
      expandedIds.add(childId);
    }
  });

  return expandedIds;
}

function treeNodeId(parentId: string, node: EndpointNode, index: number): string {
  return `${parentId}/${index}:${node.type}:${node.name}`;
}
