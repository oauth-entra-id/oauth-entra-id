import { Controller, Get } from '@nestjs/common';
import { env } from '~/env';
// biome-ignore lint/style/useImportType: NestJS
import { PublicService } from './public.service';

@Controller('')
export class PublicController {
  constructor(private readonly publicService: PublicService) {}

  @Get('')
  getHello(): { message: string } {
    return { message: this.publicService.getHello() };
  }

  @Get('health')
  getHealth(): string {
    return this.publicService.getHealth();
  }

  @Get('app-info')
  getAppId() {
    return {
      current: 'red',
      blue: env.BLUE_AZURE_CLIENT_ID,
      red: env.RED_AZURE_CLIENT_ID,
      yellow: env.YELLOW_AZURE_CLIENT_ID,
    };
  }
}
