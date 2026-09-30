// Props that make a non-button element behave as one: focusable, and
// activated by Enter/Space as well as a click.
export function clickable(activate, { stopPropagation = false } = {}) {
  return {
    role: "button",
    tabIndex: 0,
    onClick: (e) => {
      if (stopPropagation) e.stopPropagation();
      activate();
    },
    onKeyDown: (e) => {
      if (e.key !== "Enter" && e.key !== " ") return;
      e.preventDefault();
      activate();
    },
  };
}
