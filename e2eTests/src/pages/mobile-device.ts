import type { BrowserContext, Page, Response } from '@playwright/test';
import { liveEnv, type ServerName } from '../env';
import { signInAtMicrosoft } from './microsoft';
import type { MobileSite } from './mobile-app-page';

const env = liveEnv();

/** The browser of the phone, where the user signs in at Microsoft. It is a different browser than the app. */
export class SystemBrowser {
  /** Where the server sent this browser after Microsoft posted the login result to it. */
  callbackLocation: string | undefined;

  private constructor(
    readonly page: Page,
    readonly context: BrowserContext,
  ) {
    page.on('response', (response) => {
      void this.recordCallback(response);
    });
  }

  static async create(context: BrowserContext): Promise<SystemBrowser> {
    // No app is installed in this browser to receive the app's address, so that page only has to load.
    await context.route(
      (url) => url.origin === env.frontend.origin,
      (route) =>
        route.fulfill({
          status: 200,
          contentType: 'text/html',
          body: '<!doctype html><title>Back to the app</title><p>Back to the app</p>',
        }),
    );
    return new SystemBrowser(await context.newPage(), context);
  }

  private async recordCallback(response: Response): Promise<void> {
    if (!new URL(response.url()).pathname.endsWith('/auth/mobile/callback')) return;
    this.callbackLocation = (await response.allHeaders().catch(() => ({}) as Record<string, string>)).location;
  }

  async open(url: URL): Promise<void> {
    await this.page.goto(url.toString());
  }

  async completeSignIn(): Promise<void> {
    await signInAtMicrosoft(this.page, env.user, env.frontend.origin);
  }
}

/** A user with a phone: the app (the demo in Mobile mode) and the phone's system browser. */
export class Phone {
  constructor(
    readonly app: MobileSite,
    readonly systemBrowser: SystemBrowser,
  ) {}

  async startLogin(server: ServerName): Promise<URL> {
    await this.app.open(server);
    await this.app.enableMobileMode();
    return await this.app.startMicrosoftLogin();
  }

  /** Microsoft is open in the system browser: the user signs in and the system browser hands the app its address. */
  async completeLogin(): Promise<void> {
    await this.systemBrowser.completeSignIn();
    await this.app.openDeepLink();
    await this.app.expectConnected();
  }

  async finishLogin(authorizeUrl: URL): Promise<void> {
    await this.systemBrowser.open(authorizeUrl);
    await this.completeLogin();
  }

  async signIn(server: ServerName): Promise<void> {
    await this.finishLogin(await this.startLogin(server));
  }
}
