import React from 'react'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { ErrorAnnouncer } from './ErrorAnnouncer'

interface FormFieldProps {
  id: string
  label: string
  type?: string
  value: string
  onChange: (value: string) => void
  error?: string | null
  required?: boolean
  disabled?: boolean
  placeholder?: string
  description?: string
  className?: string
}

export function FormField({
  id,
  label,
  type = 'text',
  value,
  onChange,
  error,
  required = false,
  disabled = false,
  placeholder,
  description,
  className = ''
}: FormFieldProps) {
  const hasError = !!error
  
  return (
    <div className={`space-y-2 ${className}`}>
      <Label 
        htmlFor={id}
        className={hasError ? 'text-red-600' : ''}
      >
        {label}
        {required && <span className="text-red-500 ml-1" aria-label="обязательное поле">*</span>}
      </Label>
      
      <Input
        id={id}
        type={type}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        required={required}
        disabled={disabled}
        aria-invalid={hasError}
        aria-describedby={hasError ? `${id}-error` : description ? `${id}-description` : undefined}
        className={hasError ? 'border-red-500 focus:border-red-500' : ''}
      />
      
      {description && !hasError && (
        <p id={`${id}-description`} className="text-sm text-gray-600">
          {description}
        </p>
      )}
      
      {hasError && (
        <div 
          id={`${id}-error`} 
          role="alert" 
          className="text-red-600 text-sm"
          aria-live="polite"
        >
          {error}
        </div>
      )}
      
      <ErrorAnnouncer error={error} />
    </div>
  )
}

interface FormFieldGroupProps {
  children: React.ReactNode
  legend: string
  description?: string
  className?: string
}

export function FormFieldGroup({ 
  children, 
  legend, 
  description, 
  className = '' 
}: FormFieldGroupProps) {
  return (
    <fieldset className={`space-y-4 ${className}`}>
      <legend className="text-lg font-medium text-gray-900">
        {legend}
      </legend>
      {description && (
        <p className="text-sm text-gray-600">
          {description}
        </p>
      )}
      {children}
    </fieldset>
  )
}