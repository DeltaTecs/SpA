import { NavLink } from "react-router-dom";

const NAV_ITEMS = [
  { to: "/", label: "Dashboard", end: true },
  { to: "/explorer", label: "Packet Explorer", end: false },
  { to: "/test-planner", label: "Test Planner", end: false },
  { to: "/analysis-queue", label: "Analysis Queue", end: false },
  { to: "/exploit-queue", label: "Exploit Queue", end: false },
  { to: "/guided-analysis", label: "Guided Analysis", end: false },
];

export function Sidebar() {
  return (
    <aside className="sidebar">
      <div className="sidebar__brand">
        <span className="sidebar__brand-mark">◉</span>
        <span className="sidebar__brand-text">Traffic Scanner</span>
      </div>
      <nav className="sidebar__nav">
        {NAV_ITEMS.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.end}
            className={({ isActive }) =>
              `sidebar__link${isActive ? " sidebar__link--active" : ""}`
            }
          >
            {item.label}
          </NavLink>
        ))}
      </nav>
      <div className="sidebar__footer">AI-powered traffic analysis</div>
    </aside>
  );
}
