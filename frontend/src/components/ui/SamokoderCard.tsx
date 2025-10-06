import React from 'react';
import { cn } from '../../lib/utils';

interface SamokoderCardProps extends React.HTMLAttributes<HTMLDivElement> {
  variant?: 'default' | 'bordered' | 'gradient' | 'elevated';
  children: React.ReactNode;
}

const SamokoderCard: React.FC<SamokoderCardProps> = ({
  variant = 'default',
  className,
  children,
  ...props
}) => {
  const baseClasses = 'rounded-xl bg-white p-6 transition-all duration-200';
  
  const variantClasses = {
    default: 'border border-[#E2E8F0] shadow-[0_4px_6px_rgba(0,0,0,0.07)] hover:shadow-[0_8px_16px_rgba(0,0,0,0.1)] hover:transform hover:translate-y-[-2px]',
    bordered: 'border-2 border-[#0A2E50]/20 shadow-[0_4px_6px_rgba(0,0,0,0.07)]',
    gradient: 'bg-gradient-to-br from-[#0A2E50]/5 to-[#00A868]/5 border border-[#0A2E50]/10 shadow-[0_4px_6px_rgba(0,0,0,0.07)]',
    elevated: 'shadow-[0_8px_16px_rgba(0,0,0,0.1)] border border-[#E2E8F0]/50'
  };

  return (
    <div
      className={cn(
        baseClasses,
        variantClasses[variant],
        className
      )}
      {...props}
    >
      {children}
    </div>
  );
};

const SamokoderCardHeader: React.FC<React.HTMLAttributes<HTMLDivElement>> = ({
  className,
  ...props
}) => (
  <div
    className={cn('flex flex-col space-y-1.5 p-6', className)}
    {...props}
  />
);

const SamokoderCardTitle: React.FC<React.HTMLAttributes<HTMLHeadingElement>> = ({
  className,
  ...props
}) => (
  <h3
    className={cn('text-2xl font-bold leading-none tracking-tight text-[#0A2E50] mb-2', className)}
    {...props}
  />
);

const SamokoderCardDescription: React.FC<React.HTMLAttributes<HTMLParagraphElement>> = ({
  className,
  ...props
}) => (
  <p
    className={cn('text-base text-[#64748B]', className)}
    {...props}
  />
);

const SamokoderCardContent: React.FC<React.HTMLAttributes<HTMLDivElement>> = ({
  className,
  ...props
}) => (
  <div className={cn('p-6 pt-0', className)} {...props} />
);

const SamokoderCardFooter: React.FC<React.HTMLAttributes<HTMLDivElement>> = ({
  className,
  ...props
}) => (
  <div className={cn('flex items-center p-6 pt-0', className)} {...props} />
);

export {
  SamokoderCard,
  SamokoderCardHeader,
  SamokoderCardTitle,
  SamokoderCardDescription,
  SamokoderCardContent,
  SamokoderCardFooter
};