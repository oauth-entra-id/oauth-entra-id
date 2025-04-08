import { serve } from '@hono/node-server';
import { createApp } from './app';
import { env } from './env';

function bootstrap() {
  const app = createApp();
  serve(
    {
      fetch: app.fetch,
      port: env.SERVER_PORT,
    },
    (_info) => {
      console.log(
        '============= 🔥  HonoJS Server 🔥  ===========\n',
        `🚀 Server runs on: ${env.SERVER_URL}\n`,
        `👤 Client is set to: ${env.REACT_FRONTEND_URL}\n`,
        '==============================================',
      );
    },
  );
}

bootstrap();
