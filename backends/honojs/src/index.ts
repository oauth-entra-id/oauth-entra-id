import { serve } from '@hono/node-server';
import { createApp } from './app';
import { HONOJS_PORT, HONOJS_URL, REACT_FRONTEND_URL } from './env';

function bootstrap() {
  const app = createApp();
  serve(
    {
      fetch: app.fetch,
      port: HONOJS_PORT,
    },
    (_info) => {
      console.log(
        '============= 🔥  HonoJS Server 🔥  ===========\n',
        `🚀 Server runs on: ${HONOJS_URL}\n`,
        `👤 Client is set to: ${REACT_FRONTEND_URL}\n`,
        '==============================================',
      );
    },
  );
}

bootstrap();
