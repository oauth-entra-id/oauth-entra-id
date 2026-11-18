import { Module } from '@nestjs/common';
import { LiteController } from './lite.controller';
import { LiteService } from './lite.service';

@Module({
  controllers: [LiteController],
  providers: [LiteService],
})
export class LiteModule {}
