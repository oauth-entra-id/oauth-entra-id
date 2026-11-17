import { Body, Controller, Header, HttpCode, NotFoundException, Post, Res } from '@nestjs/common';
import type { Response } from 'express';
import { Public } from '~/decorators/public.decorator';
import { mobileOAuthProvider } from '~/oauth';
import { saveMobileTokens, takeMobileTokens } from '~/utils/mobile-tickets';
// biome-ignore lint/style/useImportType: NestJS
import { MobileCallbackDto, MobileLoginDto, MobileLogoutDto, MobileRefreshDto, MobileTokenDto } from './mobile.dto';
import { orClientError, withStatus } from './mobile.utils';

// Mobile flow of the package: the app gets a ticket with the login URL, opens the URL in the system browser,
// and exchanges the ticket for the tokens when it is back. Tokens travel as Bearer tokens, no cookies are set.
// See "Mobile Authentication Flow" in the README. @Public() skips the global cookie guard.
@Public()
@Controller('auth/mobile')
export class MobileAuthController {
  @Post('login')
  @HttpCode(200)
  @Header('Cache-Control', 'no-store')
  async login(@Body() body: MobileLoginDto) {
    const { authUrl, ticket } = await orClientError(() =>
      mobileOAuthProvider.getAuthUrl({
        loginPrompt: body.loginPrompt,
        email: body.email,
        frontendUrl: body.frontendUrl,
        azureId: body.azureId,
      }),
    );
    return { url: authUrl, ticket };
  }

  // Microsoft posts here (form_post). The tokens wait for the app under the ticket id, the system browser goes back to the app.
  @Post('callback')
  async callback(@Body() body: MobileCallbackDto, @Res() res: Response) {
    const { accessToken, refreshToken, frontendUrl, ticketId } = await orClientError(() =>
      mobileOAuthProvider.getTokenByCode({ code: body.code, state: body.state }),
    );

    saveMobileTokens(ticketId, { accessToken: accessToken.value, refreshToken: refreshToken.value });
    res.redirect(303, frontendUrl);
  }

  @Post('token')
  @HttpCode(200)
  @Header('Cache-Control', 'no-store')
  async token(@Body() body: MobileTokenDto) {
    const { ticketId, error } = await mobileOAuthProvider.tryDecryptTicket(body.ticket);
    if (error) throw withStatus(error, 400);

    const tokens = takeMobileTokens(ticketId);
    if (!tokens) throw new NotFoundException('Ticket is not ready, expired or already used');
    return tokens;
  }

  @Post('refresh')
  @HttpCode(200)
  @Header('Cache-Control', 'no-store')
  async refresh(@Body() body: MobileRefreshDto) {
    const rt = await mobileOAuthProvider.tryRefreshTokens(body.refreshToken);
    if (rt.error) throw withStatus(rt.error, 401);
    return { accessToken: rt.newAccessToken.value, refreshToken: rt.newRefreshToken.value };
  }

  @Post('logout')
  @HttpCode(200)
  async logout(@Body() body: MobileLogoutDto) {
    const { logoutUrl } = await orClientError(() =>
      mobileOAuthProvider.getLogoutUrl({ frontendUrl: body.frontendUrl, azureId: body.azureId }),
    );
    return { url: logoutUrl };
  }
}
