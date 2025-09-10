import { useRef, useCallback } from 'react'

export function useFocusManagement() {
  const focusRef = useRef<HTMLElement>(null)
  
  const setFocus = useCallback((element: HTMLElement | null) => {
    if (element) {
      element.focus()
      element.scrollIntoView({ behavior: 'smooth', block: 'center' })
    }
  }, [])
  
  const setFocusToRef = useCallback(() => {
    if (focusRef.current) {
      setFocus(focusRef.current)
    }
  }, [setFocus])
  
  const trapFocus = useCallback((container: HTMLElement) => {
    const focusableElements = container.querySelectorAll(
      'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
    )
    
    const firstElement = focusableElements[0] as HTMLElement
    const lastElement = focusableElements[focusableElements.length - 1] as HTMLElement
    
    const handleTabKey = (e: KeyboardEvent) => {
      if (e.key === 'Tab') {
        if (e.shiftKey) {
          if (document.activeElement === firstElement) {
            e.preventDefault()
            lastElement.focus()
          }
        } else {
          if (document.activeElement === lastElement) {
            e.preventDefault()
            firstElement.focus()
          }
        }
      }
    }
    
    container.addEventListener('keydown', handleTabKey)
    
    return () => {
      container.removeEventListener('keydown', handleTabKey)
    }
  }, [])
  
  return {
    focusRef,
    setFocus,
    setFocusToRef,
    trapFocus
  }
}