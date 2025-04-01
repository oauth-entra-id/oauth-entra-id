import type { Request, Response } from 'express';
import { OAuthError } from '~/core/OAuthError';
import type { ServerType } from '~/shared/request-extension';

type AuthenticationBody = {
  loginPrompt?: 'email' | 'select-account' | 'sso';
  email?: string;
  frontendUrl: string;
};

export const sharedHandleAuthentication = (server: ServerType) => {
  return async (req: Request, res: Response) => {
    if (!req.oauthProvider || req.serverType !== server) {
      throw new OAuthError(500, 'Make sure authConfig is set correctly and you use the correct server type');
    }

    const body = req.body as AuthenticationBody | undefined;

    const { authUrl } = await req.oauthProvider.generateAuthUrl(
      body ? { loginPrompt: body.loginPrompt, email: body.email, frontendUrl: body.frontendUrl } : {},
    );

    res.status(200).json({ url: authUrl });
  };
};

type CallbackBody = { code: string; state: string };

export const sharedHandleCallback = (server: ServerType) => {
  return async (req: Request, res: Response) => {
    if (!req.oauthProvider || req.serverType !== server) {
      throw new OAuthError(500, 'Make sure authConfig is set correctly and you use the correct server type');
    }

    const body = req.body as CallbackBody | undefined;
    if (!body) {
      throw new OAuthError(400, {
        message: 'Invalid params',
        description: 'Body must contain code and state',
      });
    }

    const { frontendUrl, accessToken, refreshToken } = await req.oauthProvider.exchangeCodeForToken({
      code: body.code,
      state: body.state,
    });

    res.cookie(accessToken.name, accessToken.value, accessToken.options);
    if (refreshToken) res.cookie(refreshToken.name, refreshToken.value, refreshToken.options);
    res.redirect(frontendUrl);
  };
};

type LogoutBody = { frontendUrl: string };

export const sharedHandleLogout = (server: ServerType) => {
  return (req: Request, res: Response) => {
    if (!req.oauthProvider || req.serverType !== server) {
      throw new OAuthError(500, 'Make sure authConfig is set correctly and you use the correct server type');
    }

    const body = req.body as LogoutBody | undefined;

    const { logoutUrl, accessToken, refreshToken } = req.oauthProvider.getLogoutUrl(
      body ? { frontendUrl: body.frontendUrl } : {},
    );

    res.cookie(accessToken.name, accessToken.value, accessToken.options);
    res.cookie(refreshToken.name, refreshToken.value, refreshToken.options);
    res.status(200).json({ url: logoutUrl });
  };
};
