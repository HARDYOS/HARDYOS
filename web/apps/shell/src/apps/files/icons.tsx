import type { ReactNode, SVGProps } from "react";
import type { Kind } from "./paths";

type IconProps = SVGProps<SVGSVGElement> & { size?: number };

function icon(paths: ReactNode, stroke = 1.8) {
  return function Icon({ size = 18, ...rest }: IconProps) {
    return (
      <svg
        width={size}
        height={size}
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth={stroke}
        strokeLinecap="round"
        strokeLinejoin="round"
        aria-hidden
        {...rest}
      >
        {paths}
      </svg>
    );
  };
}

export const HomeIcon = icon(<path d="M4 11l8-7 8 7v9a1 1 0 0 1-1 1h-4v-6h-6v6H5a1 1 0 0 1-1-1z" />);
export const FileIcon = icon(
  <>
    <path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z" />
    <path d="M14 3v5h5" />
  </>,
);
export const ImageIcon = icon(
  <>
    <rect x="3" y="4" width="18" height="16" rx="2" />
    <circle cx="9" cy="10" r="2" />
    <path d="M21 17l-5-5-9 8" />
  </>,
);
export const VideoIcon = icon(
  <>
    <rect x="3" y="5" width="13" height="14" rx="2" />
    <path d="M16 10l5-3v10l-5-3" />
  </>,
);
export const MusicIcon = icon(
  <>
    <path d="M9 18V5l11-2v13" />
    <circle cx="6" cy="18" r="3" />
    <circle cx="17" cy="16" r="3" />
  </>,
);
export const TextIcon = icon(
  <>
    <path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z" />
    <path d="M14 3v5h5M9 13h6M9 17h4" />
  </>,
);
export const PdfIcon = icon(
  <>
    <path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z" />
    <path d="M14 3v5h5M8.5 16.5h7M8.5 13h4" />
  </>,
);
export const ArchiveIcon = icon(
  <>
    <rect x="4" y="3" width="16" height="18" rx="2" />
    <path d="M12 3v2M12 7v2M12 11v2M10.5 15h3v3h-3z" />
  </>,
);
export const DocIcon = icon(
  <>
    <path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z" />
    <path d="M14 3v5h5M9 12h6M9 15h6M9 18h3" />
  </>,
);
export const DownloadIcon = icon(<path d="M12 3v12M7 10l5 5 5-5M4 20h16" />);
export const LinkIcon = icon(<path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1" />);
export const HistoryIcon = icon(<path d="M3 12a9 9 0 1 0 3-6.7M3 4v4h4M12 8v4l3 2" />);
export const ListViewIcon = icon(<path d="M8 6h13M8 12h13M8 18h13M3.5 6h.01M3.5 12h.01M3.5 18h.01" />, 2);
export const GridViewIcon = icon(
  <>
    <rect x="3" y="3" width="7" height="7" rx="1.5" />
    <rect x="14" y="3" width="7" height="7" rx="1.5" />
    <rect x="3" y="14" width="7" height="7" rx="1.5" />
    <rect x="14" y="14" width="7" height="7" rx="1.5" />
  </>,
);
export const UpIcon = icon(<path d="M12 19V5M5 12l7-7 7 7" />);
export const CopyIcon = icon(
  <>
    <rect x="8" y="8" width="13" height="13" rx="2" />
    <path d="M16 8V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h3" />
  </>,
);
export const MoveIcon = icon(<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2zM10 13h6M13 10l3 3-3 3" />);
export const EyeIcon = icon(
  <>
    <path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z" />
    <circle cx="12" cy="12" r="3" />
  </>,
);
export const NewFolderIcon = icon(<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2zM12 10v6M9 13h6" />);
export const MoreIcon = icon(<path d="M5 12h.01M12 12h.01M19 12h.01" />, 3);
export const CloseIcon = icon(<path d="M6 6l12 12M18 6L6 18" />, 2);
export const ChevronLeft = icon(<path d="M15 5l-7 7 7 7" />, 2);
export const ChevronRight = icon(<path d="M9 5l7 7-7 7" />, 2);

const KIND_ICON: Record<Kind, (p: IconProps) => ReactNode> = {
  folder: icon(<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" />),
  image: ImageIcon,
  video: VideoIcon,
  audio: MusicIcon,
  pdf: PdfIcon,
  text: TextIcon,
  archive: ArchiveIcon,
  doc: DocIcon,
  file: FileIcon,
};

export function KindIcon({ kind, size = 18 }: { kind: Kind; size?: number }) {
  const I = KIND_ICON[kind];
  return (
    <span className={`fm-kind fm-kind--${kind}`}>
      <I size={size} />
    </span>
  );
}
