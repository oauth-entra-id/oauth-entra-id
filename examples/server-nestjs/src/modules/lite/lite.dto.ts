import { IsIn } from 'class-validator';

export class LiteGetB2BInfoDto {
  @IsIn(['express', 'fastify', 'honojs'])
  app!: string;
}
