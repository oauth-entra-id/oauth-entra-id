import type { OAuthProvider } from '~/core';
import { $err, $ok, type Result, type ResultErr } from '~/error';
import type { B2BApp, OAuthConfig, OboService } from '~/types';

export function $logger({ condition, funcName, message }: { condition: boolean; funcName: string; message: string }) {
  if (condition) console.log(`[oauth-entra-id] ${funcName}: ${message}`);
}

export function $getB2BInfo(
  b2bConfig: B2BApp[] | undefined,
): Result<{ map: Map<string, B2BApp>; names: string[] } | null> {
  if (!b2bConfig) return $ok(null);

  const map = new Map(b2bConfig.map((app) => [app.appName, app]));
  const names = Array.from(map.keys());

  if (names.length !== b2bConfig.length) {
    return $err('misconfiguration', { error: 'Invalid config', description: 'B2B has duplicate names' }, 500);
  }

  return $ok({ map, names });
}

export function $getOboInfo(
  oboConfig: NonNullable<OAuthConfig['advanced']>['downstreamServices'] | undefined,
): Result<{ map: Map<string, OboService>; names: string[] } | null> {
  if (!oboConfig) return $ok(null);

  const map = new Map(
    oboConfig.services.map((service) => [
      service.serviceName,
      {
        ...service,
        secure: service.isHttps ?? oboConfig.areHttps,
        sameSite: service.isSameOrigin ?? oboConfig.areSameOrigin,
      } satisfies OboService,
    ]),
  );

  const names = Array.from(map.keys());

  if (names.length !== oboConfig.services.length) {
    return $err('misconfiguration', { error: 'Invalid config', description: 'OBO has duplicate client IDs' }, 500);
  }

  return $ok({ map, names });
}

export function $filterCoreErrors(
  err: unknown,
  method: {
    [K in keyof OAuthProvider]: OAuthProvider[K] extends (...args: any[]) => any ? K : never;
  }[keyof OAuthProvider],
): Result<never, ResultErr> {
  if (err instanceof Error) {
    return $err(
      'internal',
      { error: 'An Error occurred', description: `method: ${method}, message: ${err.message}, stack : ${err.stack}` },
      500,
    );
  }

  if (typeof err === 'string') {
    return $err('internal', { error: 'An Error occurred', description: `method: ${method}, message: ${err}` }, 500);
  }

  return $err(
    'internal',
    { error: 'Unknown error', description: `method: ${method}, error: ${JSON.stringify(err)}` },
    500,
  );
}
