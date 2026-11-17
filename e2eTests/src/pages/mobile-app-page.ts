import { type BrowserContext, expect, type Page } from '@playwright/test';
import { liveEnv, mobileReturnPath } from '../env';
import { microsoftHost } from './microsoft';
import { Site } from './site';

const env = liveEnv();

export interface MobileTokens {
  accessToken: string;
  refreshToken: string;
  mainColor: string;
  services: Record<string, string>;
}

/**
 * The app never browses Microsoft itself: the system browser does. Every navigation of the app to Microsoft is
 * stopped here and its address is handed over, so the test can open it in the phone's system browser.
 */
export class MicrosoftUrls {
  private readonly waiting: Array<(url: URL) => void> = [];

  static async block(context: BrowserContext): Promise<MicrosoftUrls> {
    const urls = new MicrosoftUrls();
    await context.route(
      (url) => url.hostname === microsoftHost,
      async (route) => {
        urls.waiting.shift()?.(new URL(route.request().url()));
        await route.abort();
      },
    );
    return urls;
  }

  next(): Promise<URL> {
    return new Promise((resolve) => this.waiting.push(resolve));
  }
}

/** The demo website running as a mobile app: Mobile mode, Bearer tokens in the app's own storage, no cookies. */
export class MobileSite extends Site {
  constructor(
    page: Page,
    context: BrowserContext,
    private readonly microsoft: MicrosoftUrls,
  ) {
    super(page, context);
  }

  async enableMobileMode(): Promise<void> {
    const toggle = this.page.getByRole('switch', { name: 'Mobile app mode' });
    if (!(await toggle.isChecked())) await toggle.click();
    await expect(toggle).toBeChecked();
  }

  /** The app asks its server for the login address, keeps the ticket and heads for Microsoft; the address is returned. */
  async startMicrosoftLogin(): Promise<URL> {
    const url = this.microsoft.next();
    await this.page.getByRole('button', { name: 'Microsoft' }).click();
    return await url;
  }

  async startEmailLogin(email: string): Promise<URL> {
    await this.typeEmail(email);
    const url = this.microsoft.next();
    await this.emailSignInButton.click();
    return await url;
  }

  /** The system browser hands the address of the app over: the app is opened on its return page. */
  async openDeepLink(): Promise<void> {
    await this.page.goto(`${env.frontend.origin}${mobileReturnPath}`);
  }

  /** The app opens the Microsoft logout page, the address is returned (the tab is closed, Microsoft is not visited). */
  async signOut(): Promise<URL> {
    const logoutUrl = this.microsoft.next();
    const [tab] = await Promise.all([
      this.context.waitForEvent('page'),
      this.page.getByRole('button', { name: 'Logout' }).click(),
    ]);
    const url = await logoutUrl;
    await tab.close();
    return url;
  }

  async storedTokens(): Promise<MobileTokens | null> {
    return await this.page.evaluate(() => JSON.parse(localStorage.getItem('mobile-tokens') ?? 'null'));
  }

  async corruptAccessToken(): Promise<void> {
    await this.corrupt('accessToken');
  }

  async corruptRefreshToken(): Promise<void> {
    await this.corrupt('refreshToken');
  }

  private async corrupt(field: 'accessToken' | 'refreshToken'): Promise<void> {
    await this.page.evaluate((name) => {
      const tokens = JSON.parse(localStorage.getItem('mobile-tokens') ?? '{}');
      tokens[name] = 'tampered';
      localStorage.setItem('mobile-tokens', JSON.stringify(tokens));
    }, field);
  }
}
