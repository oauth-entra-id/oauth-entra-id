import { Module } from '@nestjs/common';
import { ProtectRouteGuard } from '~/guards/protect-route.guard';
import { ProtectedController } from './protected.controller';

@Module({
  controllers: [ProtectedController],
  providers: [ProtectRouteGuard],
})
export class ProtectedModule {}
