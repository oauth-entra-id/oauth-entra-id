import { Controller, Get } from '@nestjs/common';
import { Public } from '~/decorators/public.decorator';
import { getRegistrationIds } from '~/env';

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
    return { current: 'red', ...getRegistrationIds() };
  }
}
