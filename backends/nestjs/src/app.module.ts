import { Module } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { EnvModule } from './modules/env.module';
import { RateLimiterModule } from './modules/rate-limiter.module';
import { PublicModule } from './modules/public/public.module';
import { AuthModule } from './modules/auth/auth.module';
import { ProtectedModule } from './modules/protected/protected.module';
import { ThrottlerGuard } from '@nestjs/throttler';

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
