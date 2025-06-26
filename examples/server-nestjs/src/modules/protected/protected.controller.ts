import { Body, Controller, Get, HttpException, Post, Req, Res } from '@nestjs/common';
import axios from 'axios';
import type { Request, Response } from 'express';
import type { UserInfo as UserInfoType } from 'oauth-entra-id';
import { handleOnBehalfOf, nestjsOAuthProvider } from 'oauth-entra-id/nestjs';
import { z } from 'zod/v4';
import { UserInfo } from '~/decorators/user-info.decorator';
import { serversMap } from '~/env';
import { generateRandomPokemon } from '~/utils/generate';
// biome-ignore lint/style/useImportType: NestJS
import { GetB2BInfoDto } from './protected.dto';

@Controller('protected')
export class ProtectedController {
  @Get('user-info')
  getUserInfo(@Req() req: Request) {
    return { user: req.userInfo };
  }

  @Post('on-behalf-of')
  async getTokenOnBehalfOf(@Req() req: Request, @Res() res: Response) {
    await handleOnBehalfOf(req, res);
  }

  @Get('b2b-info')
  sendB2BInfo(@UserInfo() userInfo: UserInfoType) {
    if (userInfo?.isApp === false) throw new HttpException('Unauthorized', 401);
    return { pokemon: generateRandomPokemon(), server: 'nestjs' };
  }

  @Post('get-b2b-info')
  async getB2BInfo(@Body() body: GetB2BInfoDto) {
    const { result } = await nestjsOAuthProvider.getB2BToken({ app: body.app });

    const serverUrl = serversMap[body.app];
    const axiosResponse = await axios.get(`${serverUrl}/protected/b2b-info`, {
      headers: { Authorization: `Bearer ${result.token}` },
    });

    const { data: b2bRes, error: b2bResError } = zB2BResponse.safeParse(axiosResponse.data);
    if (b2bResError) throw new HttpException('Invalid B2B response', 500);
    return b2bRes;
  }
}

const zB2BResponse = z.object({
  pokemon: z.string().trim().min(1).max(32),
  server: z.enum(['express', 'fastify', 'honojs']),
});
