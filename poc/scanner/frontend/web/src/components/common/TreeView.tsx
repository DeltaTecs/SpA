import { useState } from "react";
import type { EndpointNode } from "../../api/types";

interface TreeNodeProps {
  node: EndpointNode;
  depth: number;
  defaultOpen: boolean;
}

function TreeNode({ node, depth, defaultOpen }: TreeNodeProps) {
  const [open, setOpen] = useState(defaultOpen);
  const hasChildren = node.children.length > 0;

  return (
    <li className="tree__item">
      <div
        className="tree__row"
        style={{ paddingLeft: `${depth * 16}px` }}
        onClick={() => hasChildren && setOpen((v) => !v)}
        role={hasChildren ? "button" : undefined}
      >
        <span className="tree__toggle">{hasChildren ? (open ? "▾" : "▸") : "·"}</span>
        <span className={`tree__name tree__name--${node.type}`}>{node.name}</span>
        <span className="tree__count">{node.count}</span>
      </div>
      {hasChildren && open && (
        <ul className="tree__children">
          {node.children.map((child, idx) => (
            <TreeNode
              key={`${child.type}-${child.name}-${idx}`}
              node={child}
              depth={depth + 1}
              defaultOpen={depth < 1}
            />
          ))}
        </ul>
      )}
    </li>
  );
}

export function TreeView({ nodes }: { nodes: EndpointNode[] }) {
  if (nodes.length === 0) {
    return <div className="tree__empty">No HTTP endpoints recorded.</div>;
  }
  return (
    <ul className="tree">
      {nodes.map((node, idx) => (
        <TreeNode key={`${node.name}-${idx}`} node={node} depth={0} defaultOpen={idx < 1} />
      ))}
    </ul>
  );
}
