import { LiteProvider, type OAuthConfig, OAuthProvider } from 'oauth-entra-id';
import { env, type Registration, registrations } from './env';

type AzureConfig = Exclude<OAuthConfig['azure'], unknown[]>;

//! RED SERVICE
function redB2BApps({ yellow, red, blue }: Registration): Required<AzureConfig>['b2bApps'] {
  return [
    { appName: 'express', scope: yellow.exposedScope },
    { appName: 'nestjs', scope: red.exposedScope },
    { appName: 'honojs', scope: blue.exposedScope },
  ];
}

function redAzure(registration: Registration): AzureConfig {
  const { yellow, red, blue } = registration;
  return {
    clientId: red.clientId,
    tenantId: red.tenantId,
    scopes: [red.customScope],
    clientSecret: red.clientSecret,
    downstreamServices: [
      {
        serviceName: 'yellow',
        scope: yellow.exposedScope,
        serviceUrl: env.EXPRESS_URL,
        encryptionKey: env.YELLOW_SECRET_KEY,
        cryptoType: 'web-api',
      },
      {
        serviceName: 'blue',
        scope: blue.exposedScope,
        serviceUrl: env.HONOJS_URL,
        encryptionKey: env.BLUE_SECRET_KEY,
      },
    ],
    b2bApps: redB2BApps(registration),
  };
}

const oauthConfig = {
  azure: registrations.second
    ? [redAzure(registrations.first), redAzure(registrations.second)]
    : redAzure(registrations.first),
  frontendUrl: env.REACT_FRONTEND_URL,
  serverCallbackUrl: `${env.SERVER_URL}/auth/callback`,
  encryptionKey: env.RED_SECRET_KEY,
  advanced: {
    acceptB2BRequests: true,
  },
} satisfies OAuthConfig;

export const oauthProvider = new OAuthProvider(oauthConfig);

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
    clientId: registrations.first.red.clientId,
    tenantId: registrations.first.red.tenantId,
    clientSecret: registrations.first.red.clientSecret,
    b2bApps: redB2BApps(registrations.first),
  },
});
