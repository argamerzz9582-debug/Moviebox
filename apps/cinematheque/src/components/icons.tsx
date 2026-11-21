/**
 * Inline icon set.
 *
 * Hand-drawn 24px stroke icons instead of an icon package: the app uses ~10
 * glyphs, and shipping a dependency for that would cost more than these lines.
 */
import type { SVGProps } from "react";

type IconProps = SVGProps<SVGSVGElement>;

function Base({ children, ...props }: IconProps & { children: React.ReactNode }) {
  return (
    <svg
      width="18"
      height="18"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.75"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
      {...props}
    >
      {children}
    </svg>
  );
}

export const IconSearch = (p: IconProps) => (
  <Base {...p}>
    <circle cx="11" cy="11" r="7" />
    <path d="m20 20-3.5-3.5" />
  </Base>
);

export const IconFilm = (p: IconProps) => (
  <Base {...p}>
    <rect x="3" y="4" width="18" height="16" rx="2" />
    <path d="M7 4v16M17 4v16M3 12h18M3 8h4M3 16h4M17 8h4M17 16h4" />
  </Base>
);

export const IconTv = (p: IconProps) => (
  <Base {...p}>
    <rect x="2" y="7" width="20" height="13" rx="2" />
    <path d="m8 3 4 4 4-4" />
  </Base>
);

export const IconPlay = (p: IconProps) => (
  <Base {...p}>
    <path d="M8 5.5v13l11-6.5z" fill="currentColor" stroke="none" />
  </Base>
);

export const IconPause = (p: IconProps) => (
  <Base {...p}>
    <rect x="7" y="5" width="3.5" height="14" rx="1" fill="currentColor" stroke="none" />
    <rect x="13.5" y="5" width="3.5" height="14" rx="1" fill="currentColor" stroke="none" />
  </Base>
);

export const IconPlus = (p: IconProps) => (
  <Base {...p}>
    <path d="M12 5v14M5 12h14" />
  </Base>
);

export const IconClose = (p: IconProps) => (
  <Base {...p}>
    <path d="M6 6l12 12M18 6 6 18" />
  </Base>
);

export const IconCheck = (p: IconProps) => (
  <Base {...p}>
    <path d="m4 12.5 5 5L20 6.5" />
  </Base>
);

export const IconTrash = (p: IconProps) => (
  <Base {...p}>
    <path d="M4 7h16M9 7V5h6v2M6 7l1 13h10l1-13M10 11v6M14 11v6" />
  </Base>
);

export const IconFolder = (p: IconProps) => (
  <Base {...p}>
    <path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" />
  </Base>
);

export const IconVolume = (p: IconProps) => (
  <Base {...p}>
    <path d="M4 10v4h3l4 3V7L7 10z" />
    <path d="M15.5 9a4 4 0 0 1 0 6M18 6.5a7.5 7.5 0 0 1 0 11" />
  </Base>
);

export const IconMuted = (p: IconProps) => (
  <Base {...p}>
    <path d="M4 10v4h3l4 3V7L7 10z" />
    <path d="m16 10 4 4M20 10l-4 4" />
  </Base>
);

export const IconFullscreen = (p: IconProps) => (
  <Base {...p}>
    <path d="M4 9V4h5M20 9V4h-5M4 15v5h5M20 15v5h-5" />
  </Base>
);

export const IconBack = (p: IconProps) => (
  <Base {...p}>
    <path d="M15 18l-6-6 6-6" />
  </Base>
);

export const IconSkip = (p: IconProps) => (
  <Base {...p}>
    <path d="M5 5.5v13l9-6.5z" fill="currentColor" stroke="none" />
    <path d="M18 5v14" />
  </Base>
);

export const IconPip = (p: IconProps) => (
  <Base {...p}>
    <rect x="3" y="5" width="18" height="14" rx="2" />
    <rect x="12" y="11" width="7" height="6" rx="1" fill="currentColor" stroke="none" />
  </Base>
);

export const IconStar = (p: IconProps) => (
  <Base {...p}>
    <path d="m12 4 2.4 5 5.6.8-4 3.9.9 5.5-4.9-2.6-4.9 2.6.9-5.5-4-3.9 5.6-.8z" />
  </Base>
);

export const IconSort = (p: IconProps) => (
  <Base {...p}>
    <path d="M4 7h10M4 12h7M4 17h4M17 4v16m0 0 3-3m-3 3-3-3" />
  </Base>
);
