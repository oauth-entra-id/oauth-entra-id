import node from '@elysiajs/node';
import Elysia from 'elysia';

export function createApp() {
  const app = new Elysia({ adapter: node() });

  app.get('/', () => 'Hello Elysia');

  return app;
}
