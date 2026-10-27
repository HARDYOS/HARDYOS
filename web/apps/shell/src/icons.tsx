import type { SVGProps } from "react";

type IconProps = SVGProps<SVGSVGElement> & { size?: number };

function svg(paths: React.ReactNode, defaultStroke = 1.8) {
  return function Icon({ size = 18, strokeWidth, ...rest }: IconProps) {
    return (
      <svg
        width={size}
        height={size}
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth={strokeWidth ?? defaultStroke}
        strokeLinecap="round"
        strokeLinejoin="round"
        aria-hidden={rest["aria-label"] ? undefined : true}
        role={rest["aria-label"] ? "img" : undefined}
        {...rest}
      >
        {paths}
      </svg>
    );
  };
}

export const FolderIcon = svg(<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" />);
export const StorageIcon = svg(
  <>
    <ellipse cx="12" cy="5" rx="8" ry="3" />
    <path d="M4 5v14c0 1.7 3.6 3 8 3s8-1.3 8-3V5" />
    <path d="M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3" />
  </>,
);
export const SlidersIcon = svg(
  <>
    <path d="M4 6h10M18 6h2M4 12h4M12 12h8M4 18h12" />
    <circle cx="16" cy="6" r="2" />
    <circle cx="10" cy="12" r="2" />
    <circle cx="18" cy="18" r="2" />
  </>,
);
export const BagIcon = svg(
  <>
    <path d="M6 7h12l1 13H5z" />
    <path d="M9 7a3 3 0 0 1 6 0" />
  </>,
);
export const TerminalIcon = svg(
  <>
    <rect x="3" y="4" width="18" height="16" rx="2" />
    <path d="M7 9l3 3-3 3M13 15h4" />
  </>,
);
export const ActivityIcon = svg(<path d="M3 12h4l3-8 4 16 3-8h4" />);
export const ListIcon = svg(<path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01" />);
export const BellIcon = svg(
  <>
    <path d="M6 16v-5a6 6 0 0 1 12 0v5l2 2H4z" />
    <path d="M10 21h4" />
  </>,
);
export const SearchIcon = svg(
  <>
    <circle cx="11" cy="11" r="7" />
    <path d="M20 20l-3.5-3.5" />
  </>,
);
export const GridIcon = svg(
  <>
    <rect x="3" y="3" width="7" height="7" rx="2" />
    <rect x="14" y="3" width="7" height="7" rx="2" />
    <rect x="3" y="14" width="7" height="7" rx="2" />
    <rect x="14" y="14" width="7" height="7" rx="2" />
  </>,
);
export const UsersIcon = svg(
  <>
    <circle cx="9" cy="8" r="3" />
    <path d="M3 20c0-3.3 2.7-6 6-6s6 2.7 6 6M16 5a3 3 0 0 1 0 6M18 14c2 .8 3 3 3 6" />
  </>,
);
export const CpuIcon = svg(
  <>
    <rect x="6" y="6" width="12" height="12" rx="2" />
    <path d="M9 2v4M15 2v4M9 18v4M15 18v4M2 9h4M2 15h4M18 9h4M18 15h4" />
  </>,
);
/** A graphics card: board, fan and bracket. */
export const GpuIcon = svg(
  <>
    <rect x="2" y="6" width="17" height="11" rx="2" />
    <circle cx="9" cy="11.5" r="3" />
    <path d="M19 9h3M19 14h3M5 17v3M14 17v3" />
  </>,
);
export const DomainIcon = svg(
  <>
    <rect x="9" y="3" width="6" height="5" rx="1" />
    <rect x="3" y="16" width="6" height="5" rx="1" />
    <rect x="15" y="16" width="6" height="5" rx="1" />
    <path d="M12 8v4M6 16v-2h12v2" />
  </>,
);
export const ShieldIcon = svg(<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z" />);
export const InfoIcon = svg(
  <>
    <circle cx="12" cy="12" r="9" />
    <path d="M12 11v5M12 8h.01" />
  </>,
);
export const PlusIcon = svg(<path d="M12 5v14M5 12h14" />, 2);
export const TrashIcon = svg(<path d="M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3" />);
export const EditIcon = svg(<path d="M4 20h4L19 9l-4-4L4 16zM14 6l4 4" />);
export const RefreshIcon = svg(<path d="M20 11a8 8 0 0 0-14.9-3M4 4v4h4M4 13a8 8 0 0 0 14.9 3M20 20v-4h-4" />);
export const KeyIcon = svg(
  <>
    <circle cx="8" cy="15" r="4" />
    <path d="M11 12l9-9M17 6l3 3M14 9l2 2" />
  </>,
);
export const LogoutIcon = svg(<path d="M15 4h4a1 1 0 0 1 1 1v14a1 1 0 0 1-1 1h-4M10 17l-5-5 5-5M5 12h11" />);
export const CameraIcon = svg(
  <>
    <path d="M4 8h3l2-3h6l2 3h3v11H4z" />
    <circle cx="12" cy="13" r="3.5" />
  </>,
);
export const CalendarIcon = svg(
  <>
    <rect x="3" y="5" width="18" height="16" rx="2" />
    <path d="M3 10h18M8 3v4M16 3v4" />
  </>,
);
export const DiskIcon = svg(
  <>
    <rect x="3" y="4" width="18" height="16" rx="2" />
    <circle cx="12" cy="12" r="4" />
    <path d="M12 12h.01M17 17h.01" />
  </>,
);
export const LayersIcon = svg(<path d="M12 3l9 5-9 5-9-5zM3 13l9 5 9-5M3 17l9 5 9-5" />);
export const PauseIcon = svg(<path d="M8 5v14M16 5v14" />, 2.2);
export const PlayIcon = svg(<path d="M7 5l12 7-12 7z" />);
export const StopIcon = svg(<rect x="6" y="6" width="12" height="12" rx="2" />);
export const AlertIcon = svg(<path d="M12 3l9 16H3zM12 10v4M12 17h.01" />);
export const CheckIcon = svg(<path d="M5 12l5 5 9-10" />, 2.2);
export const LockIcon = svg(
  <>
    <rect x="5" y="11" width="14" height="10" rx="2" />
    <path d="M8 11V8a4 4 0 0 1 8 0v3" />
  </>,
);
export const PowerIcon = svg(<path d="M12 3v9M6.3 6.3a8 8 0 1 0 11.4 0" />);
export const RestartIcon = svg(<path d="M20 11a8 8 0 1 0-2.3 5.7M20 4v7h-7" />);
export const NetworkIcon = svg(
  <>
    <circle cx="12" cy="12" r="9" />
    <path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18" />
  </>,
);
export const ExternalIcon = svg(<path d="M14 4h6v6M20 4l-9 9M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5" />);
export const UploadIcon = svg(<path d="M12 21V9M7 14l5-5 5 5M4 5h16" />);
export const ShareIcon = svg(<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v3M3 7v10a2 2 0 0 0 2 2h6M15 19h6M18 16l3 3-3 3" />);
