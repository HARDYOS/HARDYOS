import { Fragment, type ReactNode } from "react";

// A small Markdown renderer for Notes that builds React elements (never
// HTML strings), so nothing in a note can run as script on the desktop:
// headings, paragraphs, emphasis, inline and fenced code, lists and task
// lists, quotes, rules, links (http, https and mailto only) and [[wiki
// links]] to other notes in the same folder. Raw HTML stays text.

export type Block =
  | { t: "h"; level: number; text: string }
  | { t: "p"; text: string }
  | { t: "code"; lang: string; text: string }
  | { t: "quote"; blocks: Block[] }
  | { t: "hr" }
  | { t: "list"; ordered: boolean; items: { text: string; task?: boolean; done?: boolean }[] };

const HEADING = /^(#{1,6})\s+(.*?)\s*#*\s*$/;
const BULLET = /^\s{0,3}[-*+]\s+(.*)$/;
const ORDERED = /^\s{0,3}\d{1,9}[.)]\s+(.*)$/;
const FENCE = /^\s{0,3}(```|~~~)\s*([\w+-]*)\s*$/;
const RULE = /^\s{0,3}([-*_])(\s*\1){2,}\s*$/;
const TASK = /^\[( |x|X)\]\s+(.*)$/;

/** Quotes nest at most this deep; deeper ">" lines are plain text. */
export const MAX_QUOTE_DEPTH = 8;

/** Parses Markdown into blocks. */
export function parse(src: string, depth = 0): Block[] {
  const quotes = depth < MAX_QUOTE_DEPTH;
  const lines = src.replace(/\r\n?/g, "\n").split("\n");
  const out: Block[] = [];
  let i = 0;
  while (i < lines.length) {
    const line = lines[i]!;
    if (line.trim() === "") {
      i++;
      continue;
    }
    const fence = FENCE.exec(line);
    if (fence) {
      const body: string[] = [];
      i++;
      while (i < lines.length && !lines[i]!.trim().startsWith(fence[1]!)) body.push(lines[i++]!);
      i++; // closing fence (or the end)
      out.push({ t: "code", lang: fence[2] ?? "", text: body.join("\n") });
      continue;
    }
    const h = HEADING.exec(line);
    if (h) {
      out.push({ t: "h", level: h[1]!.length, text: h[2]! });
      i++;
      continue;
    }
    if (RULE.test(line)) {
      out.push({ t: "hr" });
      i++;
      continue;
    }
    if (quotes && /^\s{0,3}>/.test(line)) {
      const inner: string[] = [];
      while (i < lines.length && /^\s{0,3}>/.test(lines[i]!)) inner.push(lines[i++]!.replace(/^\s{0,3}>\s?/, ""));
      out.push({ t: "quote", blocks: parse(inner.join("\n"), depth + 1) });
      continue;
    }
    const ordered = ORDERED.test(line);
    if (ordered || BULLET.test(line)) {
      const re = ordered ? ORDERED : BULLET;
      const items: { text: string; task?: boolean; done?: boolean }[] = [];
      while (i < lines.length && re.test(lines[i]!)) {
        const text = re.exec(lines[i]!)![1]!;
        const task = TASK.exec(text);
        items.push(task ? { text: task[2]!, task: true, done: task[1] !== " " } : { text });
        i++;
        // Indented continuation lines belong to the item.
        while (i < lines.length && /^\s{2,}\S/.test(lines[i]!) && !re.test(lines[i]!)) {
          items[items.length - 1]!.text += " " + lines[i++]!.trim();
        }
      }
      out.push({ t: "list", ordered, items });
      continue;
    }
    const para: string[] = [];
    while (
      i < lines.length &&
      lines[i]!.trim() !== "" &&
      !FENCE.test(lines[i]!) &&
      !HEADING.test(lines[i]!) &&
      !RULE.test(lines[i]!) &&
      !(quotes && /^\s{0,3}>/.test(lines[i]!)) &&
      !BULLET.test(lines[i]!) &&
      !ORDERED.test(lines[i]!)
    )
      para.push(lines[i++]!.trim());
    out.push({ t: "p", text: para.join(" ") });
  }
  return out;
}

/** Whether a link target is safe to open: http(s) and mailto only. */
export function safeHref(href: string): string | null {
  const h = href.trim();
  try {
    const u = new URL(h);
    if (u.protocol === "http:" || u.protocol === "https:" || u.protocol === "mailto:") return u.toString();
  } catch {
    /* not absolute */
  }
  return null;
}

export interface RenderOptions {
  /** Opens another note by name (a [[wiki link]]). */
  onNote?: (name: string) => void;
}

type Inline = { re: RegExp; make: (m: RegExpExecArray, key: string, opts: RenderOptions) => ReactNode };

// Earliest match wins; ties go to the first rule.
const INLINE: Inline[] = [
  { re: /`([^`]+)`/, make: (m, k) => <code key={k}>{m[1]}</code> },
  {
    re: /\[\[([^\]\n|]{1,200})(?:\|([^\]\n]{1,200}))?\]\]/,
    make: (m, k, o) => {
      const target = m[1]!.trim();
      return (
        <button key={k} type="button" className="notes-wiki" onClick={() => o.onNote?.(target)} title={`Open ${target}`}>
          {(m[2] ?? m[1])!.trim()}
        </button>
      );
    },
  },
  {
    re: /\[([^\]\n]{1,500})\]\(([^)\s]{1,2000})\)/,
    make: (m, k, o) => {
      const href = safeHref(m[2]!);
      if (!href) return <Fragment key={k}>{inline(m[1]!, o, k)}</Fragment>;
      return (
        <a key={k} href={href} target="_blank" rel="noopener noreferrer">
          {inline(m[1]!, o, k)}
        </a>
      );
    },
  },
  { re: /\*\*([^*\n]+)\*\*|__([^_\n]+)__/, make: (m, k, o) => <strong key={k}>{inline(m[1] ?? m[2]!, o, k)}</strong> },
  { re: /~~([^~\n]+)~~/, make: (m, k, o) => <del key={k}>{inline(m[1]!, o, k)}</del> },
  { re: /\*([^*\n]+)\*|\b_([^_\n]+)_\b/, make: (m, k, o) => <em key={k}>{inline(m[1] ?? m[2]!, o, k)}</em> },
];

/** Renders inline Markdown to React nodes. */
export function inline(text: string, opts: RenderOptions = {}, prefix = "i"): ReactNode[] {
  const out: ReactNode[] = [];
  let rest = text;
  let n = 0;
  while (rest) {
    let best: { m: RegExpExecArray; rule: Inline } | null = null;
    for (const rule of INLINE) {
      const m = rule.re.exec(rest);
      if (m && (!best || m.index < best.m.index)) best = { m, rule };
    }
    if (!best) {
      out.push(rest);
      break;
    }
    if (best.m.index > 0) out.push(rest.slice(0, best.m.index));
    out.push(best.rule.make(best.m, `${prefix}.${n++}`, opts));
    rest = rest.slice(best.m.index + best.m[0].length);
  }
  return out;
}

function renderBlocks(blocks: Block[], opts: RenderOptions, prefix: string): ReactNode[] {
  return blocks.map((b, i) => {
    const k = `${prefix}${i}`;
    switch (b.t) {
      case "h": {
        const H = `h${Math.min(b.level + 1, 6)}` as "h2";
        return <H key={k}>{inline(b.text, opts, k)}</H>;
      }
      case "p":
        return <p key={k}>{inline(b.text, opts, k)}</p>;
      case "code":
        return (
          <pre key={k} data-lang={b.lang || undefined}>
            <code>{b.text}</code>
          </pre>
        );
      case "quote":
        return <blockquote key={k}>{renderBlocks(b.blocks, opts, `${k}.`)}</blockquote>;
      case "hr":
        return <hr key={k} />;
      case "list": {
        const items = b.items.map((it, j) => (
          <li key={j} className={it.task ? "notes-task" : undefined}>
            {it.task && <input type="checkbox" checked={!!it.done} readOnly aria-label={it.done ? "Done" : "Not done"} />}
            {inline(it.text, opts, `${k}.${j}`)}
          </li>
        ));
        return b.ordered ? <ol key={k}>{items}</ol> : <ul key={k}>{items}</ul>;
      }
    }
    return null;
  });
}

/** A rendered note. */
export function Markdown({ source, onNote }: { source: string; onNote?: (name: string) => void }) {
  return <div className="notes-md">{renderBlocks(parse(source), { onNote }, "b")}</div>;
}
