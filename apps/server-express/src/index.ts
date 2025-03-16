import http from 'node:http';
import createApp from './app';
import { EXPRESS_FRONTEND_URL, EXPRESS_PORT, EXPRESS_URL } from './env';

function bootstrap() {
  const app = createApp();
  const server = http.createServer(app);
  server.listen(EXPRESS_PORT, '0.0.0.0', () => {
    console.log(
      '============= 📫  Express Server 📫  =============\n',
      `🚀 Server runs on: ${EXPRESS_URL}\n`,
      `👤 Client is set to: ${EXPRESS_FRONTEND_URL}\n`,
      '==============================================',
    );
  });
}

bootstrap();
