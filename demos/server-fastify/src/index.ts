import createApp from './app';
import { env } from './env';

async function bootstrap() {
  const app = await createApp();

  await app.listen({
    port: env.SERVER_PORT,
    host: '0.0.0.0',
  });

  console.log(
    '============= ⚡  Fastify Server ⚡  =============\n',
    `🚀 Server runs on: ${env.SERVER_URL}\n`,
    `👤 Client is set to: ${env.REACT_FRONTEND_URL}\n`,
    '==============================================',
  );
}

bootstrap();
