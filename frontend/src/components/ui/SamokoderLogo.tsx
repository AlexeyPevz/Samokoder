interface LogoProps {
  showText?: boolean;
  size?: 'sm' | 'md' | 'lg';
  variant?: 'default' | 'mono' | 'inverted' | 'outline' | 'negative-s';
  className?: string;
}

export function Logo({ size = 'md', variant = 'default', showText = true, className = '' }: LogoProps) {
  const sizes = {
    sm: { container: 'w-8 h-8', text: 'text-sm' },
    md: { container: 'w-12 h-12', text: 'text-xl' },
    lg: { container: 'w-16 h-16', text: 'text-3xl' }
  };

  const colors = {
    default: {
      bg: 'from-[#00A2E8] to-[#00A868]',
      text: 'text-white'
    },
    mono: {
      bg: 'from-gray-700 to-gray-900',
      text: 'text-white'
    },
    inverted: {
      bg: 'from-white to-gray-100',
      text: 'text-[#00A2E8]'
    },
    outline: {
      bg: 'from-white to-gray-100',
      text: 'text-[#00A2E8]'
    },
    'negative-s': {
      bg: 'from-gray-100 to-white',
      text: 'text-[#00A868]'
    }
  };

  return (
    <div className={`inline-flex items-center gap-3 ${className}`}>
      <div 
        className={`${sizes[size].container} bg-gradient-to-br ${colors[variant].bg} rounded-xl flex items-center justify-center ${colors[variant].text} font-bold shadow-lg`}
        role="img"
        aria-label="Логотип Samokoder"
      >
        <svg 
          viewBox="0 0 24 24" 
          fill="currentColor" 
          className="w-2/3 h-2/3"
        >
          <path d="M13 2L3 14h8l-1 8 10-12h-8l1-8z" />
        </svg>
      </div>
      {showText && (
        <span className={`${sizes[size].text} font-bold bg-gradient-to-r ${colors[variant].bg} bg-clip-text text-transparent`}>
          SAMOKODER
        </span>
      )}
    </div>
  );
}

export default Logo;

interface SamokoderLogoProps {
  size?: 'sm' | 'md' | 'lg';
  variant?: 'default' | 'mono' | 'inverted' | 'outline' | 'negative-s';
  showText?: boolean;
  className?: string;
}

export function SamokoderLogo({ size = 'md', variant = 'default', showText = true, className = '' }: SamokoderLogoProps) {
  return <Logo size={size} variant={variant} showText={showText} className={className} />;
}
