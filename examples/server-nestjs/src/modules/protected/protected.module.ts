import { Module } from '@nestjs/common';
import { ProtectRouteGuard } from '~/guards/protect-route.guard';
import { ProtectedController } from './protected.controller';
import { ProtectedService } from './protected.service';

@Module({
  controllers: [ProtectedController],
  providers: [ProtectedService, ProtectRouteGuard],
})
export class ProtectedModule {}
