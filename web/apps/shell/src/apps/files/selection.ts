/**
 * Selection in a file list, the way desktop file managers do it: a click
 * selects one, Ctrl/Cmd+click toggles, Shift+click selects a range from the
 * anchor. `focus` is the item keyboard navigation moves from.
 */
export interface Selection {
  selected: Set<string>;
  anchor: string | null;
  focus: string | null;
}

export const emptySelection = (): Selection => ({ selected: new Set(), anchor: null, focus: null });

export function clickSelect(sel: Selection, order: string[], key: string, mods: { shift?: boolean; toggle?: boolean }): Selection {
  if (mods.shift && sel.anchor && order.includes(sel.anchor)) {
    const a = order.indexOf(sel.anchor);
    const b = order.indexOf(key);
    const [lo, hi] = a < b ? [a, b] : [b, a];
    const range = order.slice(lo, hi + 1);
    const selected = mods.toggle ? new Set([...sel.selected, ...range]) : new Set(range);
    return { selected, anchor: sel.anchor, focus: key };
  }
  if (mods.toggle) {
    const selected = new Set(sel.selected);
    if (selected.has(key)) selected.delete(key);
    else selected.add(key);
    return { selected, anchor: key, focus: key };
  }
  return { selected: new Set([key]), anchor: key, focus: key };
}

/** Moves the focus by delta (arrow keys); with shift the range grows from the anchor. */
export function moveSelect(sel: Selection, order: string[], delta: number, shift: boolean): Selection {
  if (order.length === 0) return sel;
  const from = sel.focus ? order.indexOf(sel.focus) : -1;
  const i = from < 0 ? (delta > 0 ? 0 : order.length - 1) : Math.max(0, Math.min(order.length - 1, from + delta));
  const key = order[i]!;
  if (shift) return clickSelect(sel.anchor ? sel : { ...sel, anchor: sel.focus ?? key }, order, key, { shift: true });
  return { selected: new Set([key]), anchor: key, focus: key };
}

export function selectAll(order: string[]): Selection {
  return { selected: new Set(order), anchor: order[0] ?? null, focus: order[order.length - 1] ?? null };
}

/** Drops keys that are no longer in the list (after a refresh). */
export function prune(sel: Selection, order: string[]): Selection {
  const keep = new Set(order);
  const selected = new Set([...sel.selected].filter((k) => keep.has(k)));
  if (selected.size === sel.selected.size && (!sel.focus || keep.has(sel.focus))) return sel;
  return { selected, anchor: sel.anchor && keep.has(sel.anchor) ? sel.anchor : null, focus: sel.focus && keep.has(sel.focus) ? sel.focus : null };
}
