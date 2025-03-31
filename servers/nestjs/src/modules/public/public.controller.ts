import { Controller, Get } from '@nestjs/common';
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
}
