interface ColorToggleProps {
  enabled: boolean;
  onChange: (value: boolean) => void;
}

export function ColorToggle({ enabled, onChange }: ColorToggleProps) {
  return (
    <button
      type="button"
      className={`toggle${enabled ? " toggle--on" : ""}`}
      aria-pressed={enabled}
      onClick={() => onChange(!enabled)}
    >
      <span className="toggle__track">
        <span className="toggle__dot" />
      </span>
      Color by association
    </button>
  );
}
