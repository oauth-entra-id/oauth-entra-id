import { type BrowserContext, test as base, devices, expect } from '@playwright/test';
import { type ServerName, servers } from './env';
import { MobileApi } from './mobile-api-client';
import { MicrosoftUrls, MobileSite } from './pages/mobile-app-page';
import { Phone, SystemBrowser } from './pages/mobile-device';
import { Site } from './pages/site';

type StorageState = Awaited<ReturnType<BrowserContext['storageState']>>;
type MicrosoftSession = () => Promise<StorageState>;

export interface Sites {
  knownToMicrosoft(): Promise<Site>;
  signedIn(server: ServerName, options?: { freshMicrosoftSession?: boolean }): Promise<Site>;
}

export interface Phones {
  knownToMicrosoft(): Promise<Phone>;
  signedIn(server: ServerName, options?: { freshMicrosoftSession?: boolean }): Promise<Phone>;
}

const contextOptions = { locale: 'en-US', viewport: { width: 1280, height: 900 } };
const phoneOptions = { ...devices['Pixel 7'], locale: 'en-US' };

// The demo runs on the Vite dev server with the react-scan toolbar floating over the page. It can sit on top of a menu
// item and swallow the click, so it is hidden in the test browsers.
async function hideDevOverlay(context: BrowserContext): Promise<BrowserContext> {
  await context.addInitScript(() => {
    addEventListener('DOMContentLoaded', () => {
      const style = document.createElement('style');
      style.textContent = '#react-scan-root { display: none !important; }';
      document.head.append(style);
    });
  });
  return context;
}

export const test = base.extend<
  { site: Sites; phone: Phones; mobileApi: (server: ServerName) => MobileApi },
  { microsoftSession: MicrosoftSession }
>({
  microsoftSession: [
    async ({ browser }, use) => {
      let session: Promise<StorageState> | undefined;

      const create = (): Promise<StorageState> =>
        base.step(`Prepare a Microsoft session (one sign-in on ${servers.honojs.label})`, async () => {
          const context = await hideDevOverlay(await browser.newContext(contextOptions));
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
      const context = await hideDevOverlay(
        await browser.newContext({ ...contextOptions, ...(storageState ? { storageState } : {}) }),
      );
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

  // A phone is two browsers: the app (the demo in Mobile mode) and the system browser where Microsoft is visited.
  phone: async ({ browser, microsoftSession }, use) => {
    const contexts: BrowserContext[] = [];

    const newPhone = async (storageState?: StorageState): Promise<Phone> => {
      const appContext = await hideDevOverlay(await browser.newContext(phoneOptions));
      const systemContext = await browser.newContext({ ...phoneOptions, ...(storageState ? { storageState } : {}) });
      contexts.push(appContext, systemContext);
      const app = new MobileSite(await appContext.newPage(), appContext, await MicrosoftUrls.block(appContext));
      return new Phone(app, await SystemBrowser.create(systemContext));
    };

    const phones: Phones = {
      knownToMicrosoft: async () => newPhone(await microsoftSession()),
      signedIn: async (server, options) => {
        const fresh = options?.freshMicrosoftSession === true;
        const phone = fresh ? await newPhone() : await phones.knownToMicrosoft();
        await test.step(`Sign in on ${servers[server].label} from the phone${fresh ? ' with a new Microsoft session' : ''}`, async () => {
          await phone.signIn(server);
        });
        return phone;
      },
    };

    await use(phones);
    await Promise.all(contexts.map((context) => context.close()));
  },

  mobileApi: async ({ request }, use) => {
    await use((server) => new MobileApi(request, server));
  },
});

export { expect };
