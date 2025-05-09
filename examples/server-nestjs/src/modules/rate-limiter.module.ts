import { ThrottlerModule } from '@nestjs/throttler';

export const RateLimiterModule = ThrottlerModule.forRoot([
  {
    ttl: 60 * 1000,
    limit: 100,
    skipIf: (req) => req.switchToHttp().getRequest().ip === '127.0.0.6',
  },
]);
