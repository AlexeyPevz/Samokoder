interface IconProps {
  className?: string;
  size?: number;
}

export function SamokoderIcon({ className = "w-6 h-6", size }: IconProps) {
  const sizeClass = size ? `w-${size} h-${size}` : className;
  return (
    <svg 
      viewBox="0 0 24 24" 
      fill="currentColor" 
      className={sizeClass}
    >
      <path d="M13 2L3 14h8l-1 8 10-12h-8l1-8z" />
    </svg>
  );
}

export function LightningIcon({ className = "w-6 h-6", size }: IconProps) {
  return <SamokoderIcon className={className} size={size} />;
}

export function CodeBracketsIcon({ className = "w-6 h-6" }: IconProps) {
  return (
    <svg viewBox="0 0 24 24" fill="currentColor" className={className}>
      <path d="M8 3L2 12l6 9 2-1.5L5.5 12 10 4.5 8 3zm8 0l-2 1.5L18.5 12 14 19.5l2 1.5 6-9-6-9z" />
    </svg>
  );
}

export function AIBrainIcon({ className = "w-6 h-6" }: IconProps) {
  return (
    <svg viewBox="0 0 24 24" fill="currentColor" className={className}>
      <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 18c-4.41 0-8-3.59-8-8s3.59-8 8-8 8 3.59 8 8-3.59 8-8 8zm-1-13h2v6h-2zm0 8h2v2h-2z" />
    </svg>
  );
}

export function DevelopmentIcon({ className = "w-6 h-6" }: IconProps) {
  return (
    <svg viewBox="0 0 24 24" fill="currentColor" className={className}>
      <path d="M22.7 19l-9.1-9.1c.9-2.3.4-5-1.5-6.9-2-2-5-2.4-7.4-1.3L9 6 6 9 1.6 4.7C.4 7.1.9 10.1 2.9 12.1c1.9 1.9 4.6 2.4 6.9 1.5l9.1 9.1c.4.4 1 .4 1.4 0l2.3-2.3c.5-.4.5-1.1.1-1.4z" />
    </svg>
  );
}

export function PlatformIcon({ className = "w-6 h-6" }: IconProps) {
  return (
    <svg viewBox="0 0 24 24" fill="currentColor" className={className}>
      <path d="M4 6h16v2H4zm0 5h16v2H4zm0 5h16v2H4z" />
    </svg>
  );
}
