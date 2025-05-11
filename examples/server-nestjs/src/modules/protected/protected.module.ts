import { Module } from '@nestjs/common';
import { ProtectRouteGuard } from '~/guards/protect-route.guard';
import { ProtectedController } from './protected.controller';

@Module({
  providers: [ProtectRouteGuard],
  controllers: [ProtectedController],
})
export class ProtectedModule {}
