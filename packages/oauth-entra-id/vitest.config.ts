import path from 'node:path';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    watch: false,
    typecheck: {
      include: ['**/*.test.ts'],
      enabled: true,
      ignoreSourceErrors: false,
      checker: 'tsc',
      tsconfig: './tsconfig.json',
    },
    silent: false,
  },
  resolve: {
    alias: {
      '~': path.resolve(__dirname, 'src'),
    },
  },
});
