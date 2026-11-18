import { useEffect, useState } from 'react';
import { Button } from '~/components/ui/Button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '~/components/ui/Card';
import { Separator } from '~/components/ui/Separator';
import { SmallMutedText } from '~/components/ui/Text';
import { ToggleGroup, ToggleGroupItem } from '~/components/ui/ToggleGroup';
import { getLiteB2BData, hasLoginToken, type LiteB2BData, type LiteToken, verifyWithLite } from '~/services/lite';
import { useMobileStore } from '~/stores/mobile-store';
import { type Server, serversMap, useServerStore } from '~/stores/server-store';

interface Check {
  id: string;
  label: string;
  expected: number;
  run: () => Promise<number>;
}

const tokenChecks: Array<{ token: LiteToken; label: string }> = [
  { token: 'none', label: 'No token' },
  { token: 'empty', label: 'An empty bearer' },
  { token: 'garbage', label: 'Garbage' },
  { token: 'too-long', label: 'A token that is too long' },
];

const paramChecks: Array<{ id: string; label: string; body: { app?: string } }> = [
  { id: 'unknown-server', label: 'An unknown server', body: { app: 'unknown' } },
  { id: 'no-server', label: 'No server', body: {} },
];

/**
 * Manual tests of the package's LiteProvider, no login needed: it only works with plain app tokens.
 * The same in browser and mobile app mode, except for the login token that only exists in mobile app mode.
 */
export function LiteTests() {
  const server = useServerStore((state) => state.server);
  const serverLabel = useServerStore((state) => state.serverLabel);
  const mobileEnabled = useMobileStore((state) => state.enabled);
  const [results, setResults] = useState<Record<string, number>>({});
  const [target, setTarget] = useState<Server | undefined>();
  const [b2bData, setB2BData] = useState<{ status: number; data?: LiteB2BData } | undefined>();

  // Results belong to the server and the mode they were run against.
  // biome-ignore lint/correctness/useExhaustiveDependencies: reset when the server or the mode changes
  useEffect(() => {
    setResults({});
    setTarget(undefined);
    setB2BData(undefined);
  }, [server, mobileEnabled]);

  const loginToken = mobileEnabled && hasLoginToken();
  const tokenList: Check[] = [
    ...tokenChecks.map(({ token, label }) => ({
      id: token,
      label,
      expected: 401,
      run: () => verifyWithLite(token),
    })),
    ...(loginToken
      ? [
          {
            id: 'login-token',
            label: 'Your login token (encrypted)',
            expected: 401,
            run: () => verifyWithLite('login-token'),
          },
        ]
      : []),
  ];
  const paramList: Check[] = paramChecks.map(({ id, label, body }) => ({
    id,
    label,
    expected: 400,
    run: async () => (await getLiteB2BData(body)).status,
  }));

  const runCheck = async (check: Check) => {
    const status = await check.run();
    setResults((current) => ({ ...current, [check.id]: status }));
  };

  const runAll = async () => {
    setResults({});
    for (const check of [...tokenList, ...paramList]) await runCheck(check);
  };

  const getData = async () => {
    if (!target) return;
    setB2BData(undefined);
    setB2BData(await getLiteB2BData({ app: target }));
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Lite tests</CardTitle>
        <CardDescription>Tested server: {serverLabel}</CardDescription>
        <Separator />
      </CardHeader>
      <CardContent>
        <Button size="sm" variant="outline" className="w-full font-semibold" onClick={runAll}>
          Run all checks
        </Button>
        <CheckList title="1. Tokens are refused (expect 401)" checks={tokenList} results={results} onCheck={runCheck} />
        <CheckList
          title="2. Bad requests are refused (expect 400)"
          checks={paramList}
          results={results}
          onCheck={runCheck}
        />
        <Separator />
        <div className="flex flex-col items-start justify-center my-2">
          <span className="text-sm font-semibold">3. Get B2B data (the server gets an app token and uses it)</span>
          <div className="flex w-full justify-between items-center mb-1">
            <ToggleGroup
              type="single"
              className="space-x-1.5"
              value={target}
              onValueChange={(value: Server) => setTarget(value || undefined)}>
              {Object.entries(serversMap).map(
                ([key, { Icon, label, value }]) =>
                  server !== value && (
                    <ToggleGroupItem
                      key={key}
                      value={value}
                      aria-label={`Lite ${label}`}
                      size="sm"
                      className="text-[0.75rem]">
                      <Icon />
                      {label}
                    </ToggleGroupItem>
                  ),
              )}
            </ToggleGroup>
            <div className="flex-1 ml-2 max-w-32">
              <Button
                variant="outline"
                size="sm"
                className="text-sm font-semibold w-full"
                disabled={!target}
                onClick={getData}>
                Get Lite Data
              </Button>
            </div>
          </div>
          {b2bData && (
            <div data-testid="lite-b2b-result" className="text-sm">
              {b2bData.data ? (
                <>
                  ✅ <span className="font-semibold">{b2bData.data.pokemon}</span> from {b2bData.data.server}. Cached:{' '}
                  <span className="font-semibold">{b2bData.data.isCached ? 'yes' : 'no'}</span>. Expires at:{' '}
                  <span className="font-semibold">
                    {b2bData.data.expiresAt}
                    {b2bData.data.expiresAt > 0 && ` (${new Date(b2bData.data.expiresAt * 1000).toLocaleTimeString()})`}
                  </span>
                </>
              ) : (
                <>❌ {b2bData.status === 0 ? 'no answer' : `status ${b2bData.status}`}</>
              )}
            </div>
          )}
        </div>
        <SmallMutedText>
          Tampered and wrong-audience app tokens, and the configurations with and without a secret, are only covered by
          the automatic tests.
        </SmallMutedText>
      </CardContent>
    </Card>
  );
}

function CheckList({
  title,
  checks,
  results,
  onCheck,
}: {
  title: string;
  checks: Check[];
  results: Record<string, number>;
  onCheck: (check: Check) => Promise<void>;
}) {
  return (
    <div className="flex flex-col my-2">
      <span className="text-sm font-semibold">{title}</span>
      <ul className="space-y-1 mt-1">
        {checks.map((check) => {
          const status = results[check.id];
          return (
            <li key={check.id} className="flex items-center justify-between gap-2 text-sm">
              <span>{check.label}</span>
              <span className="flex items-center gap-2">
                {status !== undefined && (
                  <span data-testid={`lite-result-${check.id}`} className="font-semibold">
                    {status === check.expected ? '✅' : '❌'} {status === 0 ? 'no answer' : status}
                  </span>
                )}
                <Button size="sm" variant="outline" aria-label={`Check: ${check.label}`} onClick={() => onCheck(check)}>
                  Check
                </Button>
              </span>
            </li>
          );
        })}
      </ul>
    </div>
  );
}
