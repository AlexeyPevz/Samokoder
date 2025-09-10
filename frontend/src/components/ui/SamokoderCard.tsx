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
  const baseClasses = 'rounded-lg bg-card text-card-foreground shadow-sm';
  
  const variantClasses = {
    default: 'border border-border',
    bordered: 'border-2 border-samokoder-blue/20',
    gradient: 'bg-gradient-to-br from-samokoder-blue/5 to-samokoder-green/5 border border-samokoder-blue/10',
    elevated: 'shadow-lg border border-border/50'
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
    className={cn('text-2xl font-semibold leading-none tracking-tight text-samokoder-blue', className)}
    {...props}
  />
);

const SamokoderCardDescription: React.FC<React.HTMLAttributes<HTMLParagraphElement>> = ({
  className,
  ...props
}) => (
  <p
    className={cn('text-sm text-muted-foreground', className)}
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