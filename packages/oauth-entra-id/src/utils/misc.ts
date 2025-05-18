import { OAuthError } from '~/error';
import type { B2BService, OAuthConfig } from '~/types';

export function debugLog({ condition, funcName, message }: { condition: boolean; funcName: string; message: string }) {
  if (condition) {
    console.log(`[oauth-entra-id] ${funcName}: ${message}`);
  }
}

export function getB2BInfo(b2bServices: B2BService[] | undefined) {
  if (!b2bServices) {
    return { b2bServicesMap: undefined, b2bServicesNames: undefined };
  }

  const b2bServicesMap = new Map(b2bServices.map((service) => [service.b2bServiceName, service]));
  const b2bServicesNames = Array.from(b2bServicesMap?.keys());

  if (b2bServicesNames.length !== b2bServices.length) {
    throw new OAuthError(500, { message: 'Invalid OAuthProvider config', description: 'Duplicate services found' });
  }

  return { b2bServicesMap, b2bServicesNames };
}

export function getOnBehalfOfInfo(onBehalfOfConfig: NonNullable<OAuthConfig['advanced']>['onBehalfOf'] | undefined) {
  if (!onBehalfOfConfig) {
    return { oboServicesMap: undefined, oboServicesNames: undefined };
  }

  const oboServicesMap = new Map(
    onBehalfOfConfig.oboServices.map((service) => [
      service.oboServiceName,
      {
        ...service,
        isHttps: service.isHttps ?? onBehalfOfConfig.isHttps,
        isSameSite: service.isSameSite ?? onBehalfOfConfig.isSameSite,
      },
    ]),
  );
  const oboServicesNames = Array.from(oboServicesMap.keys());

  if (oboServicesNames.length !== onBehalfOfConfig.oboServices.length) {
    throw new OAuthError(500, { message: 'Invalid OAuthProvider config', description: 'Duplicate services found' });
  }

  return { oboServicesMap, oboServicesNames };
}
