import React from 'react';
import SamokoderLogo from '../components/ui/SamokoderLogo';
import SamokoderButton from '../components/ui/SamokoderButton';
import { SamokoderCard, SamokoderCardHeader, SamokoderCardTitle, SamokoderCardDescription, SamokoderCardContent } from '../components/ui/SamokoderCard';
import SamokoderBadge from '../components/ui/SamokoderBadge';

const BrandTest: React.FC = () => {
  return (
    <div className="min-h-screen bg-[#F8FAFC] p-8">
      <div className="max-w-4xl mx-auto space-y-8">
        {/* Заголовок */}
        <div className="text-center">
          <h1 className="text-h1 font-bold text-[#0A2E50] mb-4">Тест соответствия брендбуку</h1>
          <p className="text-lg text-[#64748B]">Проверка всех элементов на соответствие брендбуку САМОКОДЕР</p>
        </div>

        {/* Цветовая палитра */}
        <section className="bg-white rounded-xl p-6 shadow-sm border border-[#E2E8F0]">
          <h2 className="text-h2 font-bold text-[#0A2E50] border-b-2 border-[#00A868] pb-3 mb-4">Цветовая палитра</h2>
          <div className="grid grid-cols-3 gap-4">
            <div className="text-center">
              <div className="w-20 h-20 bg-[#0A2E50] rounded-lg mx-auto mb-2"></div>
              <p className="font-semibold">Primary</p>
              <p className="text-sm text-[#64748B]">#0A2E50</p>
            </div>
            <div className="text-center">
              <div className="w-20 h-20 bg-[#00A868] rounded-lg mx-auto mb-2"></div>
              <p className="font-semibold">Accent</p>
              <p className="text-sm text-[#64748B]">#00A868</p>
            </div>
            <div className="text-center">
              <div className="w-20 h-20 bg-[#F8FAFC] border border-[#E2E8F0] rounded-lg mx-auto mb-2"></div>
              <p className="font-semibold">Light BG</p>
              <p className="text-sm text-[#64748B]">#F8FAFC</p>
            </div>
          </div>
        </section>

        {/* Типографика */}
        <section className="bg-white rounded-xl p-6 shadow-sm border border-[#E2E8F0]">
          <h2 className="text-h2 font-bold text-[#0A2E50] border-b-2 border-[#00A868] pb-3 mb-4">Типографика</h2>
          <div className="space-y-4">
            <p className="font-sans">Шрифт: Open Sans (должен быть загружен)</p>
            <div>
              <h1 className="text-h1 font-bold text-[#0A2E50]">Заголовок H1 - 2.5rem</h1>
              <h2 className="text-h2 font-bold text-[#0A2E50]">Заголовок H2 - 2rem</h2>
              <h3 className="text-h3 font-semibold text-[#0A2E50]">Заголовок H3 - 1.5rem</h3>
              <p className="text-base text-[#0F172A]">Основной текст - 16px, line-height: 1.6</p>
              <p className="text-base text-[#64748B]">Вторичный текст - цвет #64748B</p>
            </div>
          </div>
        </section>

        {/* Логотип */}
        <section className="bg-white rounded-xl p-6 shadow-sm border border-[#E2E8F0]">
          <h2 className="text-h2 font-bold text-[#0A2E50] border-b-2 border-[#00A868] pb-3 mb-4">Логотип</h2>
          <div className="grid grid-cols-2 gap-6">
            <div className="text-center">
              <SamokoderLogo size="lg" variant="default" />
              <p className="mt-2 text-sm text-[#64748B]">Основной вариант</p>
            </div>
            <div className="text-center bg-[#0A2E50] p-4 rounded-lg">
              <SamokoderLogo size="lg" variant="inverted" />
              <p className="mt-2 text-sm text-white">Инвертированный</p>
            </div>
          </div>
        </section>

        {/* Кнопки */}
        <section className="bg-white rounded-xl p-6 shadow-sm border border-[#E2E8F0]">
          <h2 className="text-h2 font-bold text-[#0A2E50] border-b-2 border-[#00A868] pb-3 mb-4">Кнопки</h2>
          <div className="space-y-4">
            <div className="flex gap-4">
              <SamokoderButton variant="primary">Основная кнопка</SamokoderButton>
              <SamokoderButton variant="secondary">Вторичная кнопка</SamokoderButton>
              <SamokoderButton variant="accent">Акцентная кнопка</SamokoderButton>
            </div>
            <p className="text-sm text-[#64748B]">
              border-radius: 8px (var(--border-radius)), отступы: 12px 24px
            </p>
          </div>
        </section>

        {/* Карточки */}
        <section className="bg-white rounded-xl p-6 shadow-sm border border-[#E2E8F0]">
          <h2 className="text-h2 font-bold text-[#0A2E50] border-b-2 border-[#00A868] pb-3 mb-4">Карточки</h2>
          <div className="grid grid-cols-2 gap-4">
            <SamokoderCard>
              <SamokoderCardHeader>
                <SamokoderCardTitle>Заголовок карточки</SamokoderCardTitle>
                <SamokoderCardDescription>Описание содержимого</SamokoderCardDescription>
              </SamokoderCardHeader>
              <SamokoderCardContent>
                <p>border-radius: 12px, тень: 0 4px 6px rgba(0, 0, 0, 0.07)</p>
              </SamokoderCardContent>
            </SamokoderCard>
            <SamokoderCard variant="gradient">
              <SamokoderCardHeader>
                <SamokoderCardTitle>Градиентная карточка</SamokoderCardTitle>
                <SamokoderCardDescription>С градиентным фоном</SamokoderCardDescription>
              </SamokoderCardHeader>
            </SamokoderCard>
          </div>
        </section>

        {/* Проверочный список */}
        <section className="bg-white rounded-xl p-6 shadow-sm border border-[#E2E8F0]">
          <h2 className="text-h2 font-bold text-[#0A2E50] border-b-2 border-[#00A868] pb-3 mb-4">Проверочный список</h2>
          <ul className="space-y-2 text-[#0F172A]">
            <li>✅ Primary цвет: #0A2E50 (темно-синий)</li>
            <li>✅ Accent цвет: #00A868 (зеленый)</li>
            <li>✅ Шрифт: Open Sans</li>
            <li>✅ Логотип: фигурные скобки с молнией</li>
            <li>✅ Border radius: 8px для элементов, 12px для карточек</li>
            <li>✅ Отступы: соответствуют системе (8px, 12px, 16px, 24px, 32px)</li>
          </ul>
        </section>
      </div>
    </div>
  );
};

export default BrandTest;