import type { FileEntry } from "@hardy/api-client";
import { useEffect, useState } from "react";
import { createPortal } from "react-dom";
import { CSRF_HEADER } from "@hardy/api-client";
import { bytes } from "../../format";
import { Alert, Loading } from "../../ui";
import { ChevronLeft, ChevronRight, CloseIcon, DownloadIcon } from "./icons";
import { downloadUrl, kindOf } from "./paths";

/** How much of a text file the preview reads (with a Range request). */
export const TEXT_PREVIEW_BYTES = 256 * 1024;

function TextPreview({ src, size }: { src: string; size: number }) {
  const [text, setText] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    const ctl = new AbortController();
    setText(null);
    setError(null);
    fetch(src, { headers: { Range: `bytes=0-${TEXT_PREVIEW_BYTES - 1}`, [CSRF_HEADER]: "1" }, credentials: "same-origin", signal: ctl.signal })
      .then(async (r) => {
        if (!r.ok) throw new Error(r.status === 404 ? "The file isn't there any more." : "It couldn't be opened.");
        setText(await r.text());
      })
      .catch((err: unknown) => {
        if (!ctl.signal.aborted) setError(err instanceof Error ? err.message : "It couldn't be opened.");
      });
    return () => ctl.abort();
  }, [src]);
  if (error) return <Alert tone="bad">{error}</Alert>;
  if (text === null) return <Loading />;
  return (
    <div className="fm-preview__text">
      <pre>{text}</pre>
      {size > TEXT_PREVIEW_BYTES && (
        <p className="small muted">
          Showing the first {bytes(TEXT_PREVIEW_BYTES)} of {bytes(size)}. Download it to see the rest.
        </p>
      )}
    </div>
  );
}

/**
 * Quick preview over the File Manager: images, PDFs, text, video and audio,
 * all read from the download endpoint (video and audio seek with Range).
 * Left/Right step through the folder's previewable files; Esc closes.
 */
export function Preview({
  share,
  entries,
  index,
  onIndex,
  onClose,
}: {
  share: string;
  entries: FileEntry[];
  index: number;
  onIndex: (i: number) => void;
  onClose: () => void;
}) {
  const entry = entries[index];
  const [broken, setBroken] = useState(false);
  useEffect(() => setBroken(false), [index]);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        e.stopPropagation();
        onClose();
      } else if (e.key === "ArrowRight" && index < entries.length - 1) {
        e.stopPropagation();
        onIndex(index + 1);
      } else if (e.key === "ArrowLeft" && index > 0) {
        e.stopPropagation();
        onIndex(index - 1);
      }
    };
    document.addEventListener("keydown", onKey, true);
    return () => document.removeEventListener("keydown", onKey, true);
  }, [index, entries.length, onIndex, onClose]);
  if (!entry) return null;
  const kind = kindOf(entry);
  const src = downloadUrl(share, [entry.path], { inline: true });

  let body;
  if (broken)
    body = (
      <Alert tone="warn" title="This can't be shown here">
        Your browser can't show this file. Download it to open it.
      </Alert>
    );
  else if (kind === "image") body = <img className="fm-preview__media" src={src} alt={entry.name} onError={() => setBroken(true)} />;
  else if (kind === "video") body = <video className="fm-preview__media" src={src} controls autoPlay preload="metadata" onError={() => setBroken(true)} />;
  else if (kind === "audio") body = <audio className="fm-preview__audio" src={src} controls autoPlay preload="metadata" onError={() => setBroken(true)} />;
  else if (kind === "pdf") body = <iframe className="fm-preview__frame" src={src} title={entry.name} />;
  else if (kind === "text") body = <TextPreview src={src} size={entry.size} />;
  else body = <Alert tone="info">There's no preview for this kind of file.</Alert>;

  return createPortal(
    <div
      className="fm-preview"
      role="dialog"
      aria-modal="true"
      aria-label={`Preview of ${entry.name}`}
      onMouseDown={(e) => e.target === e.currentTarget && onClose()}
    >
      <header className="fm-preview__bar">
        <span className="fm-preview__name">{entry.name}</span>
        <span className="mono small muted">
          {index + 1} / {entries.length}
        </span>
        <a className="icon-btn" href={downloadUrl(share, [entry.path])} download aria-label={`Download ${entry.name}`} title="Download">
          <DownloadIcon size={18} />
        </a>
        <button type="button" className="icon-btn" aria-label="Close preview" onClick={onClose}>
          <CloseIcon size={18} />
        </button>
      </header>
      <div className="fm-preview__stage" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
        {index > 0 && (
          <button type="button" className="fm-preview__nav fm-preview__nav--prev" aria-label="Previous file" onClick={() => onIndex(index - 1)}>
            <ChevronLeft size={22} />
          </button>
        )}
        {body}
        {index < entries.length - 1 && (
          <button type="button" className="fm-preview__nav fm-preview__nav--next" aria-label="Next file" onClick={() => onIndex(index + 1)}>
            <ChevronRight size={22} />
          </button>
        )}
      </div>
    </div>,
    document.body,
  );
}
