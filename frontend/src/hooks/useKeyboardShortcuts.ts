import { useEffect, useCallback } from 'react'

interface KeyboardShortcut {
  key: string
  ctrlKey?: boolean
  metaKey?: boolean
  shiftKey?: boolean
  altKey?: boolean
  action: () => void
  description: string
}

export function useKeyboardShortcuts(shortcuts: KeyboardShortcut[]) {
  const handleKeyDown = useCallback((e: KeyboardEvent) => {
    const shortcut = shortcuts.find(s => 
      s.key === e.key &&
      !!s.ctrlKey === e.ctrlKey &&
      !!s.metaKey === e.metaKey &&
      !!s.shiftKey === e.shiftKey &&
      !!s.altKey === e.altKey
    )
    
    if (shortcut) {
      e.preventDefault()
      shortcut.action()
    }
  }, [shortcuts])
  
  useEffect(() => {
    document.addEventListener('keydown', handleKeyDown)
    return () => document.removeEventListener('keydown', handleKeyDown)
  }, [handleKeyDown])
}

export function useCommonShortcuts() {
  const shortcuts: KeyboardShortcut[] = [
    {
      key: 'n',
      ctrlKey: true,
      action: () => {
        // Create new project
        const createButton = document.querySelector('[data-action="create-project"]') as HTMLElement
        createButton?.click()
      },
      description: 'Создать новый проект'
    },
    {
      key: 's',
      ctrlKey: true,
      action: () => {
        // Save current work
        const saveButton = document.querySelector('[data-action="save"]') as HTMLElement
        saveButton?.click()
      },
      description: 'Сохранить текущую работу'
    },
    {
      key: 'f',
      ctrlKey: true,
      action: () => {
        // Focus search
        const searchInput = document.querySelector('[data-action="search"]') as HTMLElement
        searchInput?.focus()
      },
      description: 'Перейти к поиску'
    },
    {
      key: 'h',
      ctrlKey: true,
      action: () => {
        // Go to home
        window.location.href = '/'
      },
      description: 'Перейти на главную страницу'
    },
    {
      key: 'd',
      ctrlKey: true,
      action: () => {
        // Go to dashboard
        window.location.href = '/dashboard'
      },
      description: 'Перейти к панели управления'
    },
    {
      key: 'Escape',
      action: () => {
        // Close modals/dropdowns
        const closeButton = document.querySelector('[data-action="close"]') as HTMLElement
        closeButton?.click()
      },
      description: 'Закрыть модальные окна'
    }
  ]
  
  useKeyboardShortcuts(shortcuts)
  
  return shortcuts
}