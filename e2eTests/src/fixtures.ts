import { type BrowserContext, test as base, expect } from '@playwright/test';
import { type ServerName, servers } from './env';
import { Site } from './pages/site';

type StorageState = Awaited<ReturnType<BrowserContext['storageState']>>;
type MicrosoftSession = () => Promise<StorageState>;

export interface Sites {
  knownToMicrosoft(): Promise<Site>;
  signedIn(server: ServerName, options?: { freshMicrosoftSession?: boolean }): Promise<Site>;
}

const contextOptions = { locale: 'en-US', viewport: { width: 1280, height: 900 } };

export const test = base.extend<{ site: Sites }, { microsoftSession: MicrosoftSession }>({
  microsoftSession: [
    async ({ browser }, use) => {
      let session: Promise<StorageState> | undefined;

      const create = (): Promise<StorageState> =>
        base.step(`Prepare a Microsoft session (one sign-in on ${servers.honojs.label})`, async () => {
          const context = await browser.newContext(contextOptions);
          try {
            const site = new Site(await context.newPage(), context);
            await site.open('honojs');
            await site.signInWithMicrosoft();
            const state = await context.storageState();
            return { cookies: state.cookies.filter((cookie) => !cookie.domain.includes('localhost')), origins: [] };
          } finally {
            await context.close();
          }
        });

      await use(() => {
        session ??= create();
        return session;
      });
    },
    { scope: 'worker' },
  ],

  site: async ({ browser, microsoftSession }, use) => {
    const contexts: BrowserContext[] = [];

    const newSite = async (storageState?: StorageState): Promise<Site> => {
      const context = await browser.newContext({ ...contextOptions, ...(storageState ? { storageState } : {}) });
      contexts.push(context);
      return new Site(await context.newPage(), context);
    };

    const sites: Sites = {
      knownToMicrosoft: async () => newSite(await microsoftSession()),
      signedIn: async (server, options) => {
        const fresh = options?.freshMicrosoftSession === true;
        const site = fresh ? await newSite() : await sites.knownToMicrosoft();
        await test.step(`Sign in on ${servers[server].label}${fresh ? ' with a new Microsoft session' : ''}`, async () => {
          await site.open(server);
          await site.signInWithMicrosoft();
        });
        return site;
      },
    };

    await use(sites);
    await Promise.all(contexts.map((context) => context.close()));
  },
});

export { expect };
