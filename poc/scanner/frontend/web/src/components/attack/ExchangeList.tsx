import type { Exchange, ExchangeTaskStatus } from "../../api/types";
import { ExchangeItem } from "./ExchangeItem";
import type { EditableExchange } from "./types";

interface ExchangeListProps {
  items: EditableExchange[];
  tasks: Map<string, ExchangeTaskStatus>;
  onToggle: (id: string) => void;
  onEdit: (id: string, patch: Partial<Exchange>) => void;
  /** Selected pentest-item ids (`${exchangeId}#${idx}`) for the suggested checks. */
  selectedCheckIds: Set<string>;
  onToggleCheck: (checkId: string) => void;
  onQueueCustom: (exchangeId: string, description: string) => void;
}

export function ExchangeList({
  items,
  tasks,
  onToggle,
  onEdit,
  selectedCheckIds,
  onToggleCheck,
  onQueueCustom,
}: ExchangeListProps) {
  if (items.length === 0) {
    return <div className="muted">No interesting data exchanges in this recording.</div>;
  }
  return (
    <div className="exchange-list">
      {items.map((item) => (
        <ExchangeItem
          key={item.id}
          item={item}
          task={tasks.get(item.id)}
          onToggle={onToggle}
          onEdit={onEdit}
          selectedCheckIds={selectedCheckIds}
          onToggleCheck={onToggleCheck}
          onQueueCustom={onQueueCustom}
        />
      ))}
    </div>
  );
}
