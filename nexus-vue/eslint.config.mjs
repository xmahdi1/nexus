import js from '@eslint/js';
import vue from 'eslint-plugin-vue';
import ts from 'typescript-eslint';
import vueParser from 'vue-eslint-parser';

export default [
  { ignores: ['dist/**', 'node_modules/**'] },
  js.configs.recommended,
  ...vue.configs['flat/essential'],
  {
    files: ['**/*.ts', '**/*.vue'],
    languageOptions: {
      parser: ts.parser,
      parserOptions: { sourceType: 'module', ecmaVersion: 'latest' },
    },
    plugins: { '@typescript-eslint': ts.plugin },
    rules: {
      // TypeScript resolves browser globals and type-only declarations.
      'no-undef': 'off',
      'no-unused-vars': 'off',
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
      '@typescript-eslint/no-unused-expressions': 'error',
      'no-eval': 'error',
      'no-implied-eval': 'error',
      'no-new-func': 'error',
      'no-script-url': 'error',
    },
  },
  {
    files: ['**/*.vue'],
    languageOptions: {
      parser: vueParser,
      parserOptions: { parser: ts.parser, extraFileExtensions: ['.vue'] },
    },
  },
  {
    files: ['src/components/ui/*.vue'],
    rules: {
      'vue/multi-word-component-names': [
        'error',
        {
          ignores: [
            'Badge',
            'Button',
            'Card',
            'Dialog',
            'Input',
            'Label',
            'Select',
            'Sheet',
            'Table',
            'Tabs',
            'Textarea',
            'Tooltip',
          ],
        },
      ],
    },
  },
  {
    files: ['**/*.mjs'],
    languageOptions: {
      globals: Object.fromEntries(
        [
          'process',
          'Buffer',
          'console',
          'URL',
          'fetch',
          'setTimeout',
          'clearTimeout',
          'setInterval',
          'clearInterval',
          'WebSocket',
          'CustomEvent',
          'Response',
          'window',
          'setImmediate',
          'File',
          'AbortSignal',
        ].map((name) => [name, 'readonly']),
      ),
    },
  },
];
