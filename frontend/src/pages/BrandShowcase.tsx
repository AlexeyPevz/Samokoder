import React from 'react';
import SamokoderLogo from '../components/ui/SamokoderLogo';
import SamokoderButton from '../components/ui/SamokoderButton';
import { SamokoderCard, SamokoderCardHeader, SamokoderCardTitle, SamokoderCardDescription, SamokoderCardContent } from '../components/ui/SamokoderCard';
import SamokoderBadge from '../components/ui/SamokoderBadge';
import { SamokoderIcon, LightningIcon, CodeBracketsIcon, AIBrainIcon, DevelopmentIcon, PlatformIcon } from '../components/ui/SamokoderIcons';

const BrandShowcase: React.FC = () => {
  return (
    <div className="min-h-screen bg-background p-8">
      <div className="max-w-6xl mx-auto space-y-12">
        {/* Header */}
        <div className="text-center space-y-4">
          <h1 className="text-4xl font-bold text-samokoder-blue">
            SAMOKODER Brand Showcase
          </h1>
          <p className="text-lg text-muted-foreground">
            Демонстрация фирменного стиля и компонентов
          </p>
        </div>

        {/* Logo Variations */}
        <section className="space-y-6">
          <h2 className="text-2xl font-semibold text-samokoder-blue">Логотип и его варианты</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            <div className="space-y-4">
              <h3 className="text-lg font-medium">Основной логотип</h3>
              <SamokoderLogo variant="default" size="lg" showText={true} />
            </div>
            <div className="space-y-4">
              <h3 className="text-lg font-medium">Монохромный</h3>
              <SamokoderLogo variant="mono" size="lg" showText={true} />
            </div>
            <div className="space-y-4">
              <h3 className="text-lg font-medium">Инвертированный</h3>
              <div className="bg-samokoder-blue p-4 rounded-lg">
                <SamokoderLogo variant="inverted" size="lg" showText={true} />
              </div>
            </div>
            <div className="space-y-4">
              <h3 className="text-lg font-medium">Контурный</h3>
              <div className="bg-samokoder-blue p-4 rounded-lg">
                <SamokoderLogo variant="outline" size="lg" showText={true} />
              </div>
            </div>
            <div className="space-y-4">
              <h3 className="text-lg font-medium">Только иконка</h3>
              <SamokoderLogo variant="default" size="lg" showText={false} />
            </div>
            <div className="space-y-4">
              <h3 className="text-lg font-medium">Негативное пространство S</h3>
              <div className="bg-samokoder-blue p-4 rounded-lg">
                <SamokoderLogo variant="negative-s" size="lg" showText={true} />
              </div>
            </div>
          </div>
        </section>

        {/* Icons */}
        <section className="space-y-6">
          <h2 className="text-2xl font-semibold text-samokoder-blue">Иконки</h2>
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-6">
            <div className="text-center space-y-2">
              <SamokoderIcon size={48} />
              <p className="text-sm">Основной логотип</p>
            </div>
            <div className="text-center space-y-2">
              <LightningIcon size={48} />
              <p className="text-sm">Молния</p>
            </div>
            <div className="text-center space-y-2">
              <CodeBracketsIcon size={48} />
              <p className="text-sm">Скобки кода</p>
            </div>
            <div className="text-center space-y-2">
              <AIBrainIcon size={48} />
              <p className="text-sm">AI Мозг</p>
            </div>
            <div className="text-center space-y-2">
              <DevelopmentIcon size={48} />
              <p className="text-sm">Разработка</p>
            </div>
            <div className="text-center space-y-2">
              <PlatformIcon size={48} />
              <p className="text-sm">Платформа</p>
            </div>
          </div>
        </section>

        {/* Buttons */}
        <section className="space-y-6">
          <h2 className="text-2xl font-semibold text-samokoder-blue">Кнопки</h2>
          <div className="space-y-4">
            <div className="flex flex-wrap gap-4">
              <SamokoderButton variant="primary">Основная кнопка</SamokoderButton>
              <SamokoderButton variant="secondary">Вторичная кнопка</SamokoderButton>
              <SamokoderButton variant="accent">Акцентная кнопка</SamokoderButton>
              <SamokoderButton variant="outline">Контурная кнопка</SamokoderButton>
              <SamokoderButton variant="ghost">Призрачная кнопка</SamokoderButton>
            </div>
            <div className="flex flex-wrap gap-4">
              <SamokoderButton variant="primary" size="sm">Маленькая</SamokoderButton>
              <SamokoderButton variant="primary" size="md">Средняя</SamokoderButton>
              <SamokoderButton variant="primary" size="lg">Большая</SamokoderButton>
            </div>
          </div>
        </section>

        {/* Cards */}
        <section className="space-y-6">
          <h2 className="text-2xl font-semibold text-samokoder-blue">Карточки</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            <SamokoderCard variant="default">
              <SamokoderCardHeader>
                <SamokoderCardTitle>Обычная карточка</SamokoderCardTitle>
                <SamokoderCardDescription>
                  Стандартная карточка с базовым стилем
                </SamokoderCardDescription>
              </SamokoderCardHeader>
              <SamokoderCardContent>
                <p>Содержимое карточки с описанием функциональности.</p>
              </SamokoderCardContent>
            </SamokoderCard>

            <SamokoderCard variant="bordered">
              <SamokoderCardHeader>
                <SamokoderCardTitle>Карточка с рамкой</SamokoderCardTitle>
                <SamokoderCardDescription>
                  Карточка с выделенной рамкой в фирменных цветах
                </SamokoderCardDescription>
              </SamokoderCardHeader>
              <SamokoderCardContent>
                <p>Идеально подходит для важных элементов интерфейса.</p>
              </SamokoderCardContent>
            </SamokoderCard>

            <SamokoderCard variant="gradient">
              <SamokoderCardHeader>
                <SamokoderCardTitle>Градиентная карточка</SamokoderCardTitle>
                <SamokoderCardDescription>
                  Карточка с градиентным фоном
                </SamokoderCardDescription>
              </SamokoderCardHeader>
              <SamokoderCardContent>
                <p>Создает визуальный акцент и привлекает внимание.</p>
              </SamokoderCardContent>
            </SamokoderCard>
          </div>
        </section>

        {/* Badges */}
        <section className="space-y-6">
          <h2 className="text-2xl font-semibold text-samokoder-blue">Значки</h2>
          <div className="flex flex-wrap gap-4">
            <SamokoderBadge variant="default">Основной</SamokoderBadge>
            <SamokoderBadge variant="secondary">Вторичный</SamokoderBadge>
            <SamokoderBadge variant="accent">Акцентный</SamokoderBadge>
            <SamokoderBadge variant="outline">Контурный</SamokoderBadge>
            <SamokoderBadge variant="success">Успех</SamokoderBadge>
            <SamokoderBadge variant="warning">Предупреждение</SamokoderBadge>
            <SamokoderBadge variant="error">Ошибка</SamokoderBadge>
          </div>
          <div className="flex flex-wrap gap-4">
            <SamokoderBadge size="sm">Маленький</SamokoderBadge>
            <SamokoderBadge size="md">Средний</SamokoderBadge>
            <SamokoderBadge size="lg">Большой</SamokoderBadge>
          </div>
        </section>

        {/* Color Palette */}
        <section className="space-y-6">
          <h2 className="text-2xl font-semibold text-samokoder-blue">Цветовая палитра</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="space-y-4">
              <h3 className="text-lg font-medium">Основные цвета</h3>
              <div className="space-y-2">
                <div className="flex items-center gap-4">
                  <div className="w-16 h-16 bg-samokoder-blue rounded-lg"></div>
                  <div>
                    <p className="font-medium">SAMOKODER Blue</p>
                    <p className="text-sm text-muted-foreground">#00A2E5</p>
                  </div>
                </div>
                <div className="flex items-center gap-4">
                  <div className="w-16 h-16 bg-samokoder-green rounded-lg"></div>
                  <div>
                    <p className="font-medium">SAMOKODER Green</p>
                    <p className="text-sm text-muted-foreground">#00A868</p>
                  </div>
                </div>
              </div>
            </div>
            <div className="space-y-4">
              <h3 className="text-lg font-medium">Темные варианты</h3>
              <div className="space-y-2">
                <div className="flex items-center gap-4">
                  <div className="w-16 h-16 bg-samokoder-blue-dark rounded-lg"></div>
                  <div>
                    <p className="font-medium">SAMOKODER Blue Dark</p>
                    <p className="text-sm text-muted-foreground">Для hover состояний</p>
                  </div>
                </div>
                <div className="flex items-center gap-4">
                  <div className="w-16 h-16 bg-samokoder-green-dark rounded-lg"></div>
                  <div>
                    <p className="font-medium">SAMOKODER Green Dark</p>
                    <p className="text-sm text-muted-foreground">Для hover состояний</p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </section>
      </div>
    </div>
  );
};

export default BrandShowcase;