import { Module } from '@nestjs/common';
import { MobileService } from './mobile.service';
import { MobileAuthController } from './mobile-auth.controller';
import { MobileProtectedController } from './mobile-protected.controller';

@Module({
  controllers: [MobileAuthController, MobileProtectedController],
  providers: [MobileService],
})
export class MobileModule {}
