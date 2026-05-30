import type { VulnerabilityCheck } from "../../../api/types";

/** Optional selection control rendered as a checkbox in the card header. */
export interface CheckSelection {
  checked: boolean;
  onToggle: () => void;
}

/**
 * Renders one suggested vulnerability check. When `selection` is provided a
 * checkbox is shown in the header so the card can be picked for queueing.
 */
export function CheckCard({
  check,
  selection,
}: {
  check: VulnerabilityCheck;
  selection?: CheckSelection;
}) {
  return (
    <article className={`check${selection?.checked ? " check--selected" : ""}`}>
      <header className="check__header">
        {selection && (
          <input
            type="checkbox"
            className="check__select"
            checked={selection.checked}
            onChange={selection.onToggle}
            aria-label={`Queue "${check.title}"`}
          />
        )}
        <span className={`check__severity check__severity--${check.severity}`}>
          {check.severity}
        </span>
        <h4 className="check__title">{check.title}</h4>
      </header>
      {check.description && <p className="check__text">{check.description}</p>}
      {check.rationale && (
        <p className="check__rationale">
          <strong>Why:</strong> {check.rationale}
        </p>
      )}
      {check.technique && (
        <p className="check__meta">
          <strong>Technique:</strong> {check.technique}
        </p>
      )}
      {check.references.length > 0 && (
        <ul className="check__refs">
          {check.references.map((ref, index) => (
            <li key={index}>{renderReference(ref)}</li>
          ))}
        </ul>
      )}
    </article>
  );
}

function renderReference(ref: string) {
  if (/^https?:\/\//i.test(ref)) {
    return (
      <a href={ref} target="_blank" rel="noreferrer">
        {ref}
      </a>
    );
  }
  return <span>{ref}</span>;
}
