import http from 'node:http';
import createApp from './app';
import { env } from './env';

function bootstrap() {
  const app = createApp();
  const server = http.createServer(app);
  server.listen(env.SERVER_PORT, '0.0.0.0', () => {
    console.log(
      ' ============= 📫  Express Server 📫  ==========\n',
      `🚀 Server runs on: ${env.SERVER_URL}\n`,
      `👤 Client is set to: ${env.REACT_FRONTEND_URL}\n`,
      '==============================================',
    );
  });
}

bootstrap();
