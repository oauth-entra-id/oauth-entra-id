import { OAuthError } from '~/error';
import type { B2BApp, OAuthConfig } from '~/types';

export function debugLog({ condition, funcName, message }: { condition: boolean; funcName: string; message: string }) {
  if (condition) {
    console.log(`[oauth-entra-id] ${funcName}: ${message}`);
  }
}

export function getB2BAppsInfo(b2bClient: B2BApp[] | undefined) {
  if (!b2bClient) {
    return { b2bAppsMap: undefined, b2bAppsNames: undefined };
  }

  const b2bAppsMap = new Map(b2bClient.map((app) => [app.appName, app]));
  const b2bAppsNames = Array.from(b2bAppsMap?.keys());

  if (b2bAppsNames.length !== b2bClient.length) {
    throw new OAuthError(500, { message: 'Invalid OAuthProvider config', description: 'Duplicate services found' });
  }

  return { b2bAppsMap, b2bAppsNames };
}

export function getDownstreamServicesInfo(
  onBehalfOfConfig: NonNullable<OAuthConfig['advanced']>['downstreamServices'] | undefined,
) {
  if (!onBehalfOfConfig) {
    return { downstreamServicesMap: undefined, downstreamServicesNames: undefined };
  }

  const downstreamServicesMap = new Map(
    onBehalfOfConfig.services.map((service) => [
      service.serviceName,
      {
        ...service,
        isHttps: service.isHttps ?? onBehalfOfConfig.areHttps,
        isSameSite: service.isSameOrigin ?? onBehalfOfConfig.areSameOrigin,
      },
    ]),
  );
  const downstreamServicesNames = Array.from(downstreamServicesMap.keys());

  if (downstreamServicesNames.length !== onBehalfOfConfig.services.length) {
    throw new OAuthError(500, { message: 'Invalid OAuthProvider config', description: 'Duplicate services found' });
  }

  return { downstreamServicesMap, downstreamServicesNames };
}
