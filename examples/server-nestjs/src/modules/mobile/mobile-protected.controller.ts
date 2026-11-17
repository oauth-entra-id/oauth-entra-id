import { Body, Controller, Get, Header, HttpCode, Post, Req, UseGuards } from '@nestjs/common';
import { Public } from '~/decorators/public.decorator';
import { mobileOAuthProvider } from '~/oauth';
// biome-ignore lint/style/useImportType: NestJS
import { MobileGetB2BInfoDto, MobileOnBehalfOfDto } from './mobile.dto';
// biome-ignore lint/style/useImportType: NestJS
import { MobileService } from './mobile.service';
import { orClientError } from './mobile.utils';
import { MobileBearerGuard, type MobileRequest } from './mobile-bearer.guard';

// Mobile flow of the package, see "Mobile Middleware Flow" in the README: the app sends the access token as a Bearer token.
// @Public() skips the global cookie guard, MobileBearerGuard verifies the token with the core API of the package.
@Public()
@UseGuards(MobileBearerGuard)
@Controller('protected/mobile')
export class MobileProtectedController {
  constructor(private readonly mobileService: MobileService) {}

  @Get('user-info')
  getUserInfo(@Req() req: MobileRequest) {
    return { user: req.mobile?.user };
  }

  // The downstream tokens are returned in the body, the app sends each one as a Bearer token to its service.
  @Post('on-behalf-of')
  @HttpCode(200)
  @Header('Cache-Control', 'no-store')
  async onBehalfOf(@Req() req: MobileRequest, @Body() body: MobileOnBehalfOfDto) {
    const { results } = await orClientError(() =>
      mobileOAuthProvider.getTokenOnBehalfOf({
        accessToken: req.mobile?.jwt ?? '',
        services: body.services,
        azureId: body.azureId,
      }),
    );

    return {
      tokens: results.map(({ serviceName, accessToken }) => ({
        serviceName,
        name: accessToken.name,
        value: accessToken.value,
      })),
    };
  }

  @Post('get-b2b-info')
  @HttpCode(200)
  async getB2BInfo(@Body() body: MobileGetB2BInfoDto) {
    return await this.mobileService.fetchB2BInfo(body.app, body.azureId);
  }
}
