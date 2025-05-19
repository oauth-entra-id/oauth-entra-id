import { IsIn } from 'class-validator';

export class GetB2BInfoDto {
  @IsIn(['express', 'fastify', 'honojs'])
  appName!: string;
}
