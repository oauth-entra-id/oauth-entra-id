import createApp from './app';
import { FASTIFY_PORT, FASTIFY_URL, FASTIFY_FRONTEND_URL } from './env';

async function bootstrap() {
  const app = await createApp();

  await app.listen({
    port: FASTIFY_PORT,
    host: '0.0.0.0',
  });

  console.log(
    '============= ⚡  Fastify Server ⚡  =============\n',
    `🚀 Server runs on: ${FASTIFY_URL}\n`,
    `👤 Client is set to: ${FASTIFY_FRONTEND_URL}\n`,
    '==============================================',
  );
}

bootstrap();
