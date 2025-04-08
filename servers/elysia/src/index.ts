import { createApp } from './app';
import { env } from './env';

function bootstrap() {
  const app = createApp();
  app.listen(env.SERVER_PORT, () => {
    console.log(
      '============= 🦊  Elysia Server 🦊  ===========\n',
      `🚀 Server runs on: ${env.SERVER_URL}\n`,
      `👤 Client is set to: ${env.REACT_FRONTEND_URL}\n`,
      '==============================================',
    );
  });
}

bootstrap();
