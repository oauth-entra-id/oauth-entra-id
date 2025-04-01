import type { JwtPayload } from 'jsonwebtoken';
import type { OAuthProvider } from '~/core/OAuthProvider';

export type ServerType = 'express' | 'nestjs';

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    export interface Request {
      oauthProvider?: OAuthProvider;
      serverType: ServerType;
      areOtherSystemsAllowed: boolean;
      /**       * Stores the raw Microsoft access token and its payload.       */
      msal?: {
        microsoftToken: string;
        payload: JwtPayload;
      };
      /**       * Stores user authentication details.       *       * - If `isAnotherSystem` is `false`, the user is authenticated locally.       * - If `isAnotherSystem` is `true`, authentication comes from an external system.       */
      userInfo?:
        | { isAnotherSystem: false; uniqueId: string; roles: string[]; name: string; email: string }
        | { isAnotherSystem: true; uniqueId: string; roles: string[]; appId: string };
    }
  }
}
