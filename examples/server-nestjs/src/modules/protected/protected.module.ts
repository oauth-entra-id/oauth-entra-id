import { Module } from '@nestjs/common';
import { ProtectedController } from './protected.controller';
import { ProtectedService } from './protected.service';

@Module({
  controllers: [ProtectedController],
  providers: [ProtectedService],
})
export class ProtectedModule {}
