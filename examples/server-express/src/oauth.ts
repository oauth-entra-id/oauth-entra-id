import { LiteProvider, type OAuthConfig, OAuthProvider } from 'oauth-entra-id';
import { env, type Registration, registrations } from './env';

type AzureConfig = Exclude<OAuthConfig['azure'], unknown[]>;

//! YELLOW SERVICE
function yellowB2BApps({ red, blue }: Registration): Required<AzureConfig>['b2bApps'] {
  return [
    { appName: 'fastify', scope: red.exposedScope },
    { appName: 'honojs', scope: blue.exposedScope },
    { appName: 'nestjs', scope: red.exposedScope },
  ];
}

function yellowAzure(registration: Registration): AzureConfig {
  const { yellow, red, blue } = registration;
  return {
    clientId: yellow.clientId,
    tenantId: yellow.tenantId,
    scopes: [yellow.customScope],
    clientSecret: yellow.clientSecret,
    downstreamServices: [
      {
        serviceName: 'red',
        scope: red.exposedScope,
        serviceUrl: [env.NESTJS_URL, env.FASTIFY_URL],
        encryptionKey: env.RED_SECRET_KEY,
      },
      {
        serviceName: 'blue',
        scope: blue.exposedScope,
        serviceUrl: env.HONOJS_URL,
        encryptionKey: env.BLUE_SECRET_KEY,
      },
    ],
    b2bApps: yellowB2BApps(registration),
  };
}

export const oauthConfig = {
  azure: registrations.second
    ? [yellowAzure(registrations.first), yellowAzure(registrations.second)]
    : yellowAzure(registrations.first),
  frontendUrl: env.REACT_FRONTEND_URL,
  serverCallbackUrl: `${env.SERVER_URL}/auth/callback`,
  encryptionKey: env.YELLOW_SECRET_KEY,
  advanced: {
    acceptB2BRequests: true,
    cryptoType: 'web-api',
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

// The lite provider: plain (unencrypted) app tokens only. It verifies the ones sent to this server and gets the ones this server sends.
// It uses the first registration, the second one is only for the full provider.
export const liteProvider = new LiteProvider({
  azure: {
    clientId: registrations.first.yellow.clientId,
    tenantId: registrations.first.yellow.tenantId,
    clientSecret: registrations.first.yellow.clientSecret,
    b2bApps: yellowB2BApps(registrations.first),
  },
});
