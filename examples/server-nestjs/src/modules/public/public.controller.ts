import { Controller, Get } from '@nestjs/common';
import { Public } from '~/decorators/public.decorator';
import { env } from '~/env';

@Public()
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
      blue: { '1': env.BLUE1_AZURE_CLIENT_ID, '2': env.BLUE2_AZURE_CLIENT_ID },
      red: { '1': env.RED1_AZURE_CLIENT_ID, '2': env.RED2_AZURE_CLIENT_ID },
      yellow: { '1': env.YELLOW1_AZURE_CLIENT_ID, '2': env.YELLOW2_AZURE_CLIENT_ID },
    };
  }
}
