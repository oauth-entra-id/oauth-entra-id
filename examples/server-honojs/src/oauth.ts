import { OAuthProvider } from 'oauth-entra-id';
import { env } from './env';

//! BLUE SERVICE
export const oauthProvider = new OAuthProvider({
  azure: [
    {
      clientId: env.BLUE1_AZURE_CLIENT_ID,
      tenantId: env.BLUE1_AZURE_TENANT_ID,
      scopes: [env.BLUE1_AZURE_CUSTOM_SCOPE],
      clientSecret: env.BLUE1_AZURE_CLIENT_SECRET,
      downstreamServices: [
        {
          serviceName: 'yellow',
          scope: env.YELLOW1_AZURE_EXPOSED_SCOPE,
          serviceUrl: env.EXPRESS_URL,
          encryptionKey: env.YELLOW_SECRET_KEY,
          cryptoType: 'web-api',
        },
        {
          serviceName: 'red',
          scope: env.RED1_AZURE_EXPOSED_SCOPE,
          serviceUrl: [env.NESTJS_URL, env.FASTIFY_URL],
          encryptionKey: env.RED_SECRET_KEY,
        },
      ],
      b2bApps: [
        { appName: 'express', scope: env.YELLOW1_AZURE_EXPOSED_SCOPE },
        { appName: 'fastify', scope: env.RED1_AZURE_EXPOSED_SCOPE },
        { appName: 'nestjs', scope: env.RED1_AZURE_EXPOSED_SCOPE },
      ],
    },
    {
      clientId: env.BLUE2_AZURE_CLIENT_ID,
      tenantId: env.BLUE2_AZURE_TENANT_ID,
      scopes: [env.BLUE2_AZURE_CUSTOM_SCOPE],
      clientSecret: env.BLUE2_AZURE_CLIENT_SECRET,
      downstreamServices: [
        {
          serviceName: 'yellow',
          scope: env.YELLOW2_AZURE_EXPOSED_SCOPE,
          serviceUrl: env.EXPRESS_URL,
          encryptionKey: env.YELLOW_SECRET_KEY,
          cryptoType: 'web-api',
        },
        {
          serviceName: 'red',
          scope: env.RED2_AZURE_EXPOSED_SCOPE,
          serviceUrl: [env.NESTJS_URL, env.FASTIFY_URL],
          encryptionKey: env.RED_SECRET_KEY,
        },
      ],
      b2bApps: [
        { appName: 'express', scope: env.YELLOW2_AZURE_EXPOSED_SCOPE },
        { appName: 'fastify', scope: env.RED2_AZURE_EXPOSED_SCOPE },
        { appName: 'nestjs', scope: env.RED2_AZURE_EXPOSED_SCOPE },
      ],
    },
  ],
  frontendUrl: env.REACT_FRONTEND_URL,
  serverCallbackUrl: `${env.SERVER_URL}/auth/callback`,
  encryptionKey: env.BLUE_SECRET_KEY,
  advanced: {
    acceptB2BRequests: true,
  },
});
