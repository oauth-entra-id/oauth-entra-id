import { type BrowserContext, type Cookie, expect, type Page } from '@playwright/test';
import { type Color, liveEnv, type ServerName, servers, short } from '../env';
import { signInAtMicrosoft } from './microsoft';

const env = liveEnv();

export class Site {
  constructor(
    readonly page: Page,
    readonly context: BrowserContext,
  ) {}

  private leftTheSite = (url: URL) => url.origin !== env.frontend.origin;

  private get serverTrigger() {
    return this.page.getByRole('button', { name: /Toggle server/ });
  }

  async open(server: ServerName): Promise<void> {
    await this.page.goto(env.frontend.url);
    await this.chooseServer(server);
  }

  async chooseServer(server: ServerName): Promise<void> {
    const { label, color } = servers[server];
    await expect(this.serverTrigger).toBeVisible();
    if (!(await this.serverTrigger.innerText()).includes(label)) {
      await this.serverTrigger.click();
      await this.page.getByRole('menuitem', { name: label }).click();
    }
    await expect(this.serverTrigger).toContainText(label);
    await expect(this.page.locator('body')).toContainText(short(env.apps[color].clientId));
  }

  async setSingleSignOn(enabled: boolean): Promise<void> {
    const toggle = this.page.getByRole('switch', { name: 'Single Sign-On' });
    if ((await toggle.isChecked()) !== enabled) await toggle.click();
    if (enabled) await expect(toggle).toBeChecked();
    else await expect(toggle).not.toBeChecked();
  }

  async typeEmail(email: string): Promise<void> {
    await this.page.getByPlaceholder('nickname@email.com').fill(email);
  }

  get emailSignInButton() {
    return this.page.getByRole('button', { name: 'Sign In with Email' });
  }

  async clickMicrosoft(): Promise<void> {
    await Promise.all([
      this.page.waitForURL(this.leftTheSite, { timeout: 30_000 }),
      this.page.getByRole('button', { name: 'Microsoft' }).click(),
    ]);
  }

  async clickSignInWithEmail(email: string): Promise<void> {
    await this.typeEmail(email);
    await Promise.all([this.page.waitForURL(this.leftTheSite, { timeout: 30_000 }), this.emailSignInButton.click()]);
  }

  async completeMicrosoftSignIn(): Promise<void> {
    await signInAtMicrosoft(this.page, env.user, env.frontend.origin);
  }

  async signInWithMicrosoft(): Promise<void> {
    await this.clickMicrosoft();
    await this.completeMicrosoftSignIn();
    await this.expectConnected();
  }

  async expectGuest(): Promise<void> {
    await expect(this.page.getByText('Login into account')).toBeVisible();
  }

  async expectConnected(): Promise<void> {
    await expect(this.page.getByText('You are Connected!')).toBeVisible();
  }

  async reload(): Promise<void> {
    await this.page.reload();
    await expect(this.page.getByText(/You are Connected!|Login into account/)).toBeVisible();
  }

  async profile() {
    const text = await this.page.locator('body').innerText();
    const word = (label: string) => new RegExp(`${label}:\\s*(\\S+)`).exec(text)?.[1] ?? '';
    const injected = /Injected Data:\s*(\d+) \(Random Number\)/.exec(text)?.[1];
    return {
      name: /Name:\s*([^\n]+)/.exec(text)?.[1]?.trim() ?? '',
      email: word('Email'),
      uniqueId: word('Unique ID'),
      azure: word('Azure'),
      tenant: word('Tenant'),
      injected: injected === undefined ? undefined : Number(injected),
    };
  }

  async expectToast(text: string | RegExp): Promise<void> {
    await expect(this.page.getByText(text).first()).toBeVisible();
  }

  async selectDownstream(colorNames: Color[]): Promise<void> {
    for (const color of colorNames) await this.page.getByRole('button', { name: color, exact: true }).click();
  }

  async getTokens(): Promise<void> {
    await this.page.getByRole('button', { name: 'Get Tokens' }).click();
  }

  async getB2BData(target: ServerName): Promise<void> {
    await this.page.getByRole('radio', { name: servers[target].label, exact: true }).click();
    await this.page.getByRole('button', { name: 'Get Data' }).click();
    await this.expectToast(new RegExp(`.+ from ${target} app!`));
    await expect(this.page.locator('body')).toContainText(/\(Pokemon: [^)]+\)/);
  }

  async logout(): Promise<{ tab: Page; logoutUrl: URL }> {
    const [tab, request] = await Promise.all([
      this.context.waitForEvent('page'),
      this.context.waitForEvent('request', (candidate) => candidate.url().includes('/oauth2/v2.0/logout')),
      this.page.getByRole('button', { name: 'Logout' }).click(),
    ]);
    return { tab, logoutUrl: new URL(request.url()) };
  }

  async sessionCookies(): Promise<Cookie[]> {
    return (await this.context.cookies()).filter((cookie) => /^(at|rt)-/.test(cookie.name));
  }

  async cookie(name: string): Promise<Cookie | undefined> {
    return (await this.context.cookies()).find((cookie) => cookie.name === name);
  }

  async hasCookie(name: string): Promise<boolean> {
    return (await this.cookie(name)) !== undefined;
  }

  async removeCookie(name: string): Promise<void> {
    await this.context.clearCookies({ name });
  }

  async tamperCookie(name: string): Promise<void> {
    const cookie = await this.cookie(name);
    if (!cookie) throw new Error(`Cookie ${name} is not in the browser`);
    await this.context.addCookies([{ ...cookie, value: 'tampered' }]);
  }

  async browserStorage(): Promise<string> {
    return await this.page.evaluate(() =>
      JSON.stringify([{ ...localStorage }, { ...sessionStorage }, document.cookie, document.body.innerText]),
    );
  }

  async visit(url: string): Promise<{ status: number; text: string }> {
    const tab = await this.context.newPage();
    try {
      const response = await tab.goto(url);
      return { status: response?.status() ?? 0, text: (await response?.text()) ?? '' };
    } finally {
      await tab.close();
    }
  }
}
