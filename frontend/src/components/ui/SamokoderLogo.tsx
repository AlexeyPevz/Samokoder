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
      bg: 'from-[#0A2E50] to-[#00A868]',
      text: 'text-white'
    },
    mono: {
      bg: 'from-gray-700 to-gray-900',
      text: 'text-white'
    },
    inverted: {
      bg: 'from-white to-gray-100',
      text: 'text-[#0A2E50]'
    },
    outline: {
      bg: 'from-white to-gray-100',
      text: 'text-[#0A2E50]'
    },
    'negative-s': {
      bg: 'from-gray-100 to-white',
      text: 'text-[#00A868]'
    }
  };

  return (
    <div className={`inline-flex items-center gap-3 ${className}`}>
      <div 
        className={`${sizes[size].container} rounded-xl flex items-center justify-center relative`}
        role="img"
        aria-label="Логотип Samokoder"
      >
        <svg 
          viewBox="0 0 100 100" 
          className="w-full h-full"
        >
          {variant === 'outline' ? (
            <>
              {/* Outline version */}
              <path d="M20 25 C15 25, 10 30, 10 35 L10 65 C10 70, 15 75, 20 75" 
                    stroke="#0A2E50" strokeWidth="3" fill="none" strokeLinecap="round"/>
              <path d="M80 25 C85 25, 90 30, 90 35 L90 65 C90 70, 85 75, 80 75" 
                    stroke="#0A2E50" strokeWidth="3" fill="none" strokeLinecap="round"/>
              <path d="M45 30 L35 50 L45 50 L40 70 L60 45 L50 45 L55 30 Z" 
                    fill="none" stroke="#00A868" strokeWidth="2"/>
            </>
          ) : variant === 'inverted' ? (
            <>
              {/* Inverted version */}
              <path d="M20 25 C15 25, 10 30, 10 35 L10 65 C10 70, 15 75, 20 75" 
                    stroke="#FFFFFF" strokeWidth="4" fill="none" strokeLinecap="round"/>
              <path d="M80 25 C85 25, 90 30, 90 35 L90 65 C90 70, 85 75, 80 75" 
                    stroke="#FFFFFF" strokeWidth="4" fill="none" strokeLinecap="round"/>
              <path d="M45 30 L35 50 L45 50 L40 70 L60 45 L50 45 L55 30 Z" 
                    fill="#00A868" stroke="#00A868" strokeWidth="1"/>
            </>
          ) : variant === 'mono' ? (
            <>
              {/* Monochrome version */}
              <path d="M20 25 C15 25, 10 30, 10 35 L10 65 C10 70, 15 75, 20 75" 
                    stroke="#4B5563" strokeWidth="4" fill="none" strokeLinecap="round"/>
              <path d="M80 25 C85 25, 90 30, 90 35 L90 65 C90 70, 85 75, 80 75" 
                    stroke="#4B5563" strokeWidth="4" fill="none" strokeLinecap="round"/>
              <path d="M45 30 L35 50 L45 50 L40 70 L60 45 L50 45 L55 30 Z" 
                    fill="#6B7280" stroke="#6B7280" strokeWidth="1"/>
            </>
          ) : (
            <>
              {/* Default version - matches brandbook exactly */}
              <path d="M20 25 C15 25, 10 30, 10 35 L10 65 C10 70, 15 75, 20 75" 
                    stroke="#0A2E50" strokeWidth="4" fill="none" strokeLinecap="round"/>
              <path d="M80 25 C85 25, 90 30, 90 35 L90 65 C90 70, 85 75, 80 75" 
                    stroke="#0A2E50" strokeWidth="4" fill="none" strokeLinecap="round"/>
              <path d="M45 30 L35 50 L45 50 L40 70 L60 45 L50 45 L55 30 Z" 
                    fill="#00A868" stroke="#00A868" strokeWidth="1"/>
            </>
          )}
        </svg>
      </div>
      {showText && (
        <span className={`${sizes[size].text} font-bold text-[#0A2E50] uppercase tracking-[0.05em]`} style={{ fontFamily: 'var(--font-family)' }}>
          САМОКОДЕР
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
