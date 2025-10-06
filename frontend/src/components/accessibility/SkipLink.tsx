import React from 'react'

interface SkipLinkProps {
  href: string
  children: React.ReactNode
  className?: string
}

export function SkipLink({ href, children, className = '' }: SkipLinkProps) {
  return (
    <a
      href={href}
      className={`sr-only focus:not-sr-only focus:absolute focus:top-4 focus:left-4 focus:z-50 focus:px-4 focus:py-2 focus:bg-blue-600 focus:text-white focus:rounded-md focus:shadow-lg focus:outline-none focus:ring-2 focus:ring-blue-300 focus:ring-offset-2 ${className}`}
      onClick={(e) => {
        e.preventDefault()
        const target = document.querySelector(href)
        if (target) {
          target.scrollIntoView({ behavior: 'smooth' })
          ;(target as HTMLElement).focus()
        }
      }}
    >
      {children}
    </a>
  )
}

export function SkipLinks() {
  return (
    <div className="skip-links">
      <SkipLink href="#main-content">
        Перейти к основному контенту
      </SkipLink>
      <SkipLink href="#navigation">
        Перейти к навигации
      </SkipLink>
      <SkipLink href="#search">
        Перейти к поиску
      </SkipLink>
    </div>
  )
}