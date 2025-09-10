import React from 'react'

export function ScreenReaderSupport() {
  return (
    <div className="sr-only">
      <h1>Самокодер - AI платформа для генерации кода</h1>
      <p>
        Добро пожаловать в Самокодер. Используйте Tab для навигации, 
        Enter для активации элементов, Escape для закрытия модальных окон.
      </p>
      <h2>Горячие клавиши:</h2>
      <ul>
        <li>Ctrl+N - Создать новый проект</li>
        <li>Ctrl+S - Сохранить текущую работу</li>
        <li>Ctrl+F - Перейти к поиску</li>
        <li>Ctrl+H - Перейти на главную страницу</li>
        <li>Ctrl+D - Перейти к панели управления</li>
        <li>Escape - Закрыть модальные окна</li>
      </ul>
    </div>
  )
}

interface PageTitleProps {
  title: string
  description?: string
}

export function PageTitle({ title, description }: PageTitleProps) {
  React.useEffect(() => {
    document.title = `${title} - Самокодер`
  }, [title])
  
  return (
    <div className="sr-only">
      <h1>{title}</h1>
      {description && <p>{description}</p>}
    </div>
  )
}

interface HeadingStructureProps {
  level: 1 | 2 | 3 | 4 | 5 | 6
  children: React.ReactNode
  className?: string
}

export function HeadingStructure({ level, children, className = '' }: HeadingStructureProps) {
  const Tag = `h${level}` as keyof JSX.IntrinsicElements
  
  return (
    <Tag className={className}>
      {children}
    </Tag>
  )
}