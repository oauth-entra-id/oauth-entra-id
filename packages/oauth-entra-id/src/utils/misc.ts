import { OAuthError } from '~/error';
import type { B2BApp, OAuthConfig } from '~/types';

export function $logger({ condition, funcName, message }: { condition: boolean; funcName: string; message: string }) {
  if (condition) {
    console.log(`[oauth-entra-id] ${funcName}: ${message}`);
  }
}

export function $getB2BInfo(b2bClient: B2BApp[] | undefined) {
  if (!b2bClient) {
    return { b2bAppsMap: undefined, b2bAppNames: undefined };
  }

  const b2bAppsMap = new Map(b2bClient.map((app) => [app.appName, app]));
  const b2bAppNames = Array.from(b2bAppsMap?.keys());

  if (b2bAppNames.length !== b2bClient.length) {
    throw new OAuthError(500, { message: 'Invalid OAuthProvider config', description: 'Duplicate services found' });
  }

  return { b2bAppsMap, b2bAppNames };
}

export function $getOboInfo(onBehalfOfConfig: NonNullable<OAuthConfig['advanced']>['downstreamServices'] | undefined) {
  if (!onBehalfOfConfig) {
    return { downstreamServicesMap: undefined, downstreamServiceNames: undefined };
  }

  const downstreamServicesMap = new Map(
    onBehalfOfConfig.services.map((service) => [
      service.clientId,
      {
        ...service,
        isHttps: service.isHttps ?? onBehalfOfConfig.areHttps,
        isSameSite: service.isSameOrigin ?? onBehalfOfConfig.areSameOrigin,
      },
    ]),
  );
  const downstreamServiceNames = Array.from(downstreamServicesMap.keys());

  if (downstreamServiceNames.length !== onBehalfOfConfig.services.length) {
    throw new OAuthError(500, { message: 'Invalid OAuthProvider config', description: 'Duplicate services found' });
  }

  return { downstreamServicesMap, downstreamServiceNames };
}
