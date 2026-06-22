import type { EndpointNode } from "../../api/types";
import { TreeView } from "../common/TreeView";

export function EndpointTree({ nodes }: { nodes: EndpointNode[] }) {
  return <TreeView nodes={nodes} />;
}
