import React from 'react';
import { cn } from '../../lib/utils';

interface IconProps {
  className?: string;
  size?: number;
}

// Main logo icon with brackets and lightning
export const SamokoderIcon: React.FC<IconProps> = ({ className, size = 24 }) => (
  <svg
    width={size}
    height={size}
    viewBox="0 0 24 24"
    fill="none"
    className={cn('text-samokoder-blue', className)}
  >
    {/* Left bracket */}
    <path
      d="M8 4C8 2.89543 8.89543 2 10 2H12C13.1046 2 14 2.89543 14 4V6C14 6.55228 13.5523 7 13 7H11C10.4477 7 10 6.55228 10 6V4H8Z"
      fill="currentColor"
    />
    <path
      d="M8 8C8 7.44772 8.44772 7 9 7H11C11.5523 7 12 7.44772 12 8V16C12 16.5523 11.5523 17 11 17H9C8.44772 17 8 16.5523 8 16V8Z"
      fill="currentColor"
    />
    <path
      d="M8 18C8 16.8954 8.89543 16 10 16H12C13.1046 16 14 16.8954 14 18V20C14 21.1046 13.1046 22 12 22H10C8.89543 22 8 21.1046 8 20V18Z"
      fill="currentColor"
    />
    
    {/* Right bracket */}
    <path
      d="M16 4C16 2.89543 15.1046 2 14 2H12C10.8954 2 10 2.89543 10 4V6C10 6.55228 10.4477 7 11 7H13C13.5523 7 14 6.55228 14 6V4H16Z"
      fill="currentColor"
    />
    <path
      d="M16 8C16 7.44772 15.5523 7 15 7H13C12.4477 7 12 7.44772 12 8V16C12 16.5523 12.4477 17 13 17H15C15.5523 17 16 16.5523 16 16V8Z"
      fill="currentColor"
    />
    <path
      d="M16 18C16 16.8954 15.1046 16 14 16H12C10.8954 16 10 16.8954 10 18V20C10 21.1046 10.8954 22 12 22H14C15.1046 22 16 21.1046 16 20V18Z"
      fill="currentColor"
    />
    
    {/* Lightning bolt */}
    <path
      d="M13 2L3 14H12L11 22L21 10H12L13 2Z"
      fill="#00A868"
    />
  </svg>
);

// Lightning bolt icon
export const LightningIcon: React.FC<IconProps> = ({ className, size = 24 }) => (
  <svg
    width={size}
    height={size}
    viewBox="0 0 24 24"
    fill="none"
    className={cn('text-samokoder-green', className)}
  >
    <path
      d="M13 2L3 14H12L11 22L21 10H12L13 2Z"
      fill="currentColor"
    />
  </svg>
);

// Code brackets icon
export const CodeBracketsIcon: React.FC<IconProps> = ({ className, size = 24 }) => (
  <svg
    width={size}
    height={size}
    viewBox="0 0 24 24"
    fill="none"
    className={cn('text-samokoder-blue', className)}
  >
    <path
      d="M8 4C8 2.89543 8.89543 2 10 2H12C13.1046 2 14 2.89543 14 4V6C14 6.55228 13.5523 7 13 7H11C10.4477 7 10 6.55228 10 6V4H8Z"
      fill="currentColor"
    />
    <path
      d="M8 8C8 7.44772 8.44772 7 9 7H11C11.5523 7 12 7.44772 12 8V16C12 16.5523 11.5523 17 11 17H9C8.44772 17 8 16.5523 8 16V8Z"
      fill="currentColor"
    />
    <path
      d="M8 18C8 16.8954 8.89543 16 10 16H12C13.1046 16 14 16.8954 14 18V20C14 21.1046 13.1046 22 12 22H10C8.89543 22 8 21.1046 8 20V18Z"
      fill="currentColor"
    />
    <path
      d="M16 4C16 2.89543 15.1046 2 14 2H12C10.8954 2 10 2.89543 10 4V6C10 6.55228 10.4477 7 11 7H13C13.5523 7 14 6.55228 14 6V4H16Z"
      fill="currentColor"
    />
    <path
      d="M16 8C16 7.44772 15.5523 7 15 7H13C12.4477 7 12 7.44772 12 8V16C12 16.5523 12.4477 17 13 17H15C15.5523 17 16 16.5523 16 16V8Z"
      fill="currentColor"
    />
    <path
      d="M16 18C16 16.8954 15.1046 16 14 16H12C10.8954 16 10 16.8954 10 18V20C10 21.1046 10.8954 22 12 22H14C15.1046 22 16 21.1046 16 20V18Z"
      fill="currentColor"
    />
  </svg>
);

// AI Brain icon
export const AIBrainIcon: React.FC<IconProps> = ({ className, size = 24 }) => (
  <svg
    width={size}
    height={size}
    viewBox="0 0 24 24"
    fill="none"
    className={cn('text-samokoder-green', className)}
  >
    <path
      d="M12 2C8.5 2 6 4.5 6 8C6 9.5 6.5 10.8 7.3 11.8C6.8 12.3 6.5 13 6.5 13.8C6.5 15.2 7.6 16.3 9 16.3H10.5C10.8 16.3 11 16.5 11 16.8V18.5C11 19.3 11.7 20 12.5 20H13.5C14.3 20 15 19.3 15 18.5V16.8C15 16.5 15.2 16.3 15.5 16.3H17C18.4 16.3 19.5 15.2 19.5 13.8C19.5 13 19.2 12.3 18.7 11.8C19.5 10.8 20 9.5 20 8C20 4.5 17.5 2 14 2H12Z"
      fill="currentColor"
    />
    <circle cx="9" cy="8" r="1" fill="white" />
    <circle cx="15" cy="8" r="1" fill="white" />
    <path d="M9 12C9 12.5 9.5 13 10 13C10.5 13 11 12.5 11 12C11 11.5 10.5 11 10 11C9.5 11 9 11.5 9 12Z" fill="white" />
  </svg>
);

// Development icon
export const DevelopmentIcon: React.FC<IconProps> = ({ className, size = 24 }) => (
  <svg
    width={size}
    height={size}
    viewBox="0 0 24 24"
    fill="none"
    className={cn('text-samokoder-blue', className)}
  >
    <rect x="3" y="3" width="18" height="18" rx="2" stroke="currentColor" strokeWidth="2" fill="none" />
    <path d="M9 9H15V15H9V9Z" fill="currentColor" />
    <path d="M3 9H6V12H3V9Z" fill="currentColor" />
    <path d="M18 9H21V12H18V9Z" fill="currentColor" />
    <path d="M3 15H6V18H3V15Z" fill="currentColor" />
    <path d="M18 15H21V18H18V15Z" fill="currentColor" />
  </svg>
);

// Platform icon
export const PlatformIcon: React.FC<IconProps> = ({ className, size = 24 }) => (
  <svg
    width={size}
    height={size}
    viewBox="0 0 24 24"
    fill="none"
    className={cn('text-samokoder-green', className)}
  >
    <rect x="2" y="4" width="20" height="16" rx="2" stroke="currentColor" strokeWidth="2" fill="none" />
    <path d="M6 8H18V10H6V8Z" fill="currentColor" />
    <path d="M6 12H14V14H6V12Z" fill="currentColor" />
    <path d="M6 16H12V18H6V16Z" fill="currentColor" />
  </svg>
);