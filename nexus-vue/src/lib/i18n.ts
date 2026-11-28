import { createI18n } from 'vue-i18n';
import en from '@/locales/en.json';
import de from '@/locales/de.json';
import fr from '@/locales/fr.json';

const stored = typeof window !== 'undefined' ? localStorage.getItem('nexus_lang') : null;

export const i18n = createI18n({
  legacy: false,
  locale: stored || 'en',
  fallbackLocale: 'en',
  messages: { en, de, fr },
});
