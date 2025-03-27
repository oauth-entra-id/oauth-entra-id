import { Injectable } from '@nestjs/common';

@Injectable()
export class PublicService {
  getHello(): string {
    return 'Hello World!';
  }

  getHealth(): string {
    return 'OK';
  }
}
