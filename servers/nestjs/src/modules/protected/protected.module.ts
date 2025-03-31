import { Module } from '@nestjs/common';
import { ProtectedController } from './protected.controller';
import { ProtectRouteGuard } from '~/guards/protect-route.guard';

@Module({
  providers: [ProtectRouteGuard],
  controllers: [ProtectedController],
})
export class ProtectedModule {}
