import { IsIn, IsOptional, IsUUID } from 'class-validator';

export class GetB2BInfoDto {
  @IsIn(['express', 'fastify', 'honojs'])
  app!: string;
  @IsUUID()
  @IsOptional()
  azureId?: string;
}
