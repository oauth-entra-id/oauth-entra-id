import { defineConfig } from 'tsdown';

export default defineConfig({
  entry: ['src/index.ts'],
  clean: true,
  format: ['esm'],
  dts: false,
  tsconfig: 'tsconfig.json',
  sourcemap: true,
  minify: true,
  outExtensions: () => ({ js: '.js' }),
});
