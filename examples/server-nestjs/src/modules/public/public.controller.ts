import { Controller, Get } from '@nestjs/common';
import { env } from '~/env';

@Controller('')
export class PublicController {
  @Get('')
  getHello(): { message: string } {
    return { message: 'Hello World' };
  }

  @Get('health')
  getHealth(): string {
    return 'OK';
  }

  @Get('app-info')
  getAppId() {
    return {
      current: 'red',
      blue: env.AZURE_BLUE_CLIENT_ID,
      red: env.AZURE_RED_CLIENT_ID,
      yellow: env.AZURE_YELLOW_CLIENT_ID,
    };
  }
}
