import {
  ArrayNotEmpty,
  IsArray,
  IsEmail,
  IsIn,
  IsNotEmpty,
  IsOptional,
  IsString,
  IsUrl,
  IsUUID,
} from 'class-validator';

export class MobileLoginDto {
  @IsOptional()
  @IsIn(['email', 'select-account', 'sso'])
  loginPrompt?: 'email' | 'select-account' | 'sso';
  @IsOptional()
  @IsEmail()
  email?: string;
  @IsOptional()
  @IsUrl({ require_tld: false })
  frontendUrl?: string;
  @IsOptional()
  @IsUUID()
  azureId?: string;
}

export class MobileCallbackDto {
  @IsString()
  @IsNotEmpty()
  code!: string;
  @IsString()
  @IsNotEmpty()
  state!: string;
}

export class MobileTokenDto {
  @IsString()
  @IsNotEmpty()
  ticket!: string;
}

export class MobileRefreshDto {
  @IsString()
  @IsNotEmpty()
  refreshToken!: string;
}

export class MobileLogoutDto {
  @IsOptional()
  @IsUrl({ require_tld: false })
  frontendUrl?: string;
  @IsOptional()
  @IsUUID()
  azureId?: string;
}

export class MobileOnBehalfOfDto {
  @IsArray()
  @ArrayNotEmpty()
  @IsString({ each: true })
  services!: string[];
  @IsOptional()
  @IsUUID()
  azureId?: string;
}

export class MobileGetB2BInfoDto {
  @IsIn(['express', 'fastify', 'honojs'])
  app!: string;
  @IsOptional()
  @IsUUID()
  azureId?: string;
}
