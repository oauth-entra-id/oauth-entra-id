import { createApp } from './app';
import { ELYSIA_PORT, ELYSIA_URL, REACT_FRONTEND_URL } from './env';

function bootstrap() {
  const app = createApp();
  app.listen(ELYSIA_PORT, () => {
    console.log(
      '============= 🦊  Elysia Server 🦊  ===========\n',
      `🚀 Server runs on: ${ELYSIA_URL}\n`,
      `👤 Client is set to: ${REACT_FRONTEND_URL}\n`,
      '==============================================',
    );
  });
}

bootstrap();
