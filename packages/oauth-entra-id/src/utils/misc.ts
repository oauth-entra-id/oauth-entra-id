import type { OAuthProvider } from '~/core';
import { $err, $ok, type Result, type ResultErr } from '~/error';
import type { B2BApp, OAuthConfig, OboService } from '~/types';

export function $getB2BInfo(
  b2bConfig: B2BApp[] | undefined,
): Result<{ b2bMap: Map<string, B2BApp> | undefined; b2bNames: string[] | undefined }> {
  if (!b2bConfig) return $ok({ b2bMap: undefined, b2bNames: undefined });

  const b2bMap = new Map(b2bConfig.map((app) => [app.appName, app]));
  const b2bNames = Array.from(b2bMap.keys());

  if (b2bNames.length !== b2bConfig.length) {
    return $err('misconfiguration', { error: 'Invalid config', description: 'B2B has duplicate names', status: 500 });
  }

  return $ok({ b2bMap, b2bNames });
}

export function $getOboInfo(
  oboConfig: NonNullable<OAuthConfig['advanced']>['downstreamServices'] | undefined,
): Result<{ oboMap: Map<string, OboService> | undefined; oboNames: string[] | undefined }> {
  if (!oboConfig) return $ok({ oboMap: undefined, oboNames: undefined });

  const oboMap = new Map(
    oboConfig.services.map((service) => [
      service.serviceName,
      {
        ...service,
        secure: service.isHttps ?? oboConfig.areHttps,
        sameSite: service.isSameOrigin ?? oboConfig.areSameOrigin,
      } satisfies OboService,
    ]),
  );

  const oboNames = Array.from(oboMap.keys());

  if (oboNames.length !== oboConfig.services.length) {
    return $err('misconfiguration', {
      error: 'Invalid config',
      description: 'OBO has duplicate client IDs',
      status: 500,
    });
  }

  return $ok({ oboMap, oboNames });
}

export function $filterCoreErrors(
  err: unknown,
  method: {
    [K in keyof OAuthProvider]: OAuthProvider[K] extends (...args: any[]) => any ? K : never;
  }[keyof OAuthProvider],
): Result<never, ResultErr> {
  if (err instanceof Error) {
    return $err('internal', {
      error: 'An Error occurred',
      description: `method: ${method}, message: ${err.message}, stack : ${err.stack}`,
      status: 500,
    });
  }

  if (typeof err === 'string') {
    return $err('internal', {
      error: 'An Error occurred',
      description: `method: ${method}, message: ${err}`,
      status: 500,
    });
  }

  return $err('internal', {
    error: 'Unknown error',
    description: `method: ${method}, error: ${JSON.stringify(err)}`,
    status: 500,
  });
}
