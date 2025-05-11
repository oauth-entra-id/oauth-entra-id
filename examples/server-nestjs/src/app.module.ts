import { Module } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { ThrottlerGuard } from '@nestjs/throttler';
import { AuthModule } from './modules/auth/auth.module';
import { EnvModule } from './modules/env.module';
import { ProtectedModule } from './modules/protected/protected.module';
import { PublicModule } from './modules/public/public.module';
import { RateLimiterModule } from './modules/rate-limiter.module';

@Module({
  imports: [EnvModule, RateLimiterModule, PublicModule, AuthModule, ProtectedModule],
  providers: [
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard,
    },
  ],
})
export class AppModule {}
