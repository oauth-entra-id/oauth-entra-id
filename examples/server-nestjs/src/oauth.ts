import { type OAuthConfig, OAuthProvider } from 'oauth-entra-id';
import { env } from './env';

//! RED SERVICE
export const oauthConfig = {
  azure: [
    {
      clientId: env.RED1_AZURE_CLIENT_ID,
      tenantId: env.RED1_AZURE_TENANT_ID,
      scopes: [env.RED1_AZURE_CUSTOM_SCOPE],
      clientSecret: env.RED1_AZURE_CLIENT_SECRET,
      downstreamServices: [
        {
          serviceName: 'yellow',
          scope: env.YELLOW1_AZURE_EXPOSED_SCOPE,
          serviceUrl: env.EXPRESS_URL,
          encryptionKey: env.YELLOW_SECRET_KEY,
          cryptoType: 'web-api',
        },
        {
          serviceName: 'blue',
          scope: env.BLUE1_AZURE_EXPOSED_SCOPE,
          serviceUrl: env.HONOJS_URL,
          encryptionKey: env.BLUE_SECRET_KEY,
        },
      ],
      b2bApps: [
        { appName: 'express', scope: env.YELLOW1_AZURE_EXPOSED_SCOPE },
        { appName: 'fastify', scope: env.RED1_AZURE_EXPOSED_SCOPE },
        { appName: 'honojs', scope: env.BLUE1_AZURE_EXPOSED_SCOPE },
      ],
    },
    {
      clientId: env.RED2_AZURE_CLIENT_ID,
      tenantId: env.RED2_AZURE_TENANT_ID,
      scopes: [env.RED2_AZURE_CUSTOM_SCOPE],
      clientSecret: env.RED2_AZURE_CLIENT_SECRET,
      downstreamServices: [
        {
          serviceName: 'yellow',
          scope: env.YELLOW2_AZURE_EXPOSED_SCOPE,
          serviceUrl: env.EXPRESS_URL,
          encryptionKey: env.YELLOW_SECRET_KEY,
          cryptoType: 'web-api',
        },
        {
          serviceName: 'blue',
          scope: env.BLUE2_AZURE_EXPOSED_SCOPE,
          serviceUrl: env.HONOJS_URL,
          encryptionKey: env.BLUE_SECRET_KEY,
        },
      ],
      b2bApps: [
        { appName: 'express', scope: env.YELLOW2_AZURE_EXPOSED_SCOPE },
        { appName: 'fastify', scope: env.RED2_AZURE_EXPOSED_SCOPE },
        { appName: 'honojs', scope: env.BLUE2_AZURE_EXPOSED_SCOPE },
      ],
    },
  ],
  frontendUrl: env.REACT_FRONTEND_URL,
  serverCallbackUrl: `${env.SERVER_URL}/auth/callback`,
  encryptionKey: env.RED_SECRET_KEY,
  advanced: {
    acceptB2BRequests: true,
  },
} satisfies OAuthConfig;

// Mobile apps get their own provider and callback URL (register `<server>/auth/mobile/callback` in Entra ID), so the cookie flow above stays as it is.
// Same registrations and keys: the tokens are the same encrypted tokens. Bearer tokens on the mobile routes must belong to users, not apps.
export const mobileOAuthProvider = new OAuthProvider({
  ...oauthConfig,
  frontendUrl: env.MOBILE_RETURN_URL,
  serverCallbackUrl: `${env.SERVER_URL}/auth/mobile/callback`,
  advanced: { ...oauthConfig.advanced, acceptB2BRequests: false },
});
