import { expect, type Locator, type Page, test } from '@playwright/test';
import type { Credentials } from '../env';

export const microsoftHost = 'login.microsoftonline.com';

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function where(page: Page): string {
  const url = new URL(page.url());
  return `${url.hostname}${url.pathname}`;
}

function shown(locator: Locator): Locator {
  return locator.filter({ visible: true }).first();
}

function accountTile(page: Page, user: Credentials): Locator {
  return shown(
    page
      .locator(`[data-test-id="${user.email}" i]`)
      .or(page.getByRole('button', { name: new RegExp(escapeRegExp(user.email), 'i') })),
  );
}

function emailField(page: Page): Locator {
  return shown(page.locator('input[name="loginfmt"]'));
}

function passwordField(page: Page): Locator {
  return shown(page.locator('input[name="passwd"]:not([aria-hidden="true"])'));
}

export function signInPrompt(page: Page, user: Credentials): Locator {
  return emailField(page).or(passwordField(page)).or(accountTile(page, user)).first();
}

async function typeSecret(input: Locator, submit: Locator, value: string, field: string): Promise<void> {
  try {
    await input.fill(value);
    const accepted = await expect(submit)
      .toBeEnabled({ timeout: 1_500 })
      .then(
        () => true,
        () => false,
      );
    if (!accepted) {
      await input.fill('');
      await input.pressSequentially(value, { delay: 30 });
    }
  } catch {
    throw new Error(`Could not type the ${field} on the Microsoft sign-in page`);
  }
}

async function pressAndWait(button: Locator, leaving: Locator, problem: Locator): Promise<void> {
  await button.click();
  await Promise.race([
    leaving.waitFor({ state: 'hidden', timeout: 30_000 }),
    problem.waitFor({ state: 'visible', timeout: 30_000 }),
  ]).catch(() => undefined);
}

async function describe(locator: Locator): Promise<string> {
  const text = await locator.innerText({ timeout: 2_000 }).catch(() => '');
  return text.replace(/\s+/g, ' ').trim().slice(0, 300);
}

async function runSignIn(page: Page, user: Credentials, returnOrigin: string): Promise<void> {
  const primary = page.locator('#idSIButton9');
  const email = emailField(page);
  const password = passwordField(page);
  const tile = accountTile(page, user);
  const staySignedIn = shown(page.getByText('Stay signed in?'));
  const consent = shown(page.getByText(/Permissions requested|Review permissions/));
  const skip = shown(page.getByText(/skip for now/i));
  const problem = shown(page.locator('#usernameError, #passwordError').or(page.getByText(/AADSTS\d+/)));
  const anything = problem.or(email).or(password).or(tile).or(staySignedIn).or(consent).or(skip);
  const backOnSite = (url: URL) => url.origin === returnOrigin;

  const deadline = Date.now() + 120_000;
  while (Date.now() < deadline) {
    if (backOnSite(new URL(page.url()))) return;

    await Promise.race([
      anything.first().waitFor({ state: 'visible', timeout: 30_000 }),
      page.waitForURL(backOnSite, { timeout: 30_000 }),
    ]).catch(() => undefined);
    if (backOnSite(new URL(page.url()))) return;

    if (await problem.isVisible()) {
      throw new Error(`Microsoft reported: ${await describe(problem)}`);
    }
    if (await password.isVisible()) {
      await typeSecret(password, primary, user.password, 'password');
      await pressAndWait(primary, password, problem);
    } else if (await email.isVisible()) {
      await typeSecret(email, primary, user.email, 'email');
      await pressAndWait(primary, email, problem);
    } else if (await tile.isVisible()) {
      await tile.click();
      await tile.waitFor({ state: 'hidden', timeout: 30_000 }).catch(() => undefined);
    } else if (await staySignedIn.isVisible()) {
      await pressAndWait(primary, staySignedIn, problem);
    } else if (await consent.isVisible()) {
      await pressAndWait(primary, consent, problem);
    } else if (await skip.isVisible()) {
      await skip.click();
    }
  }
  throw new Error(`Microsoft sign-in did not finish, the browser is at ${where(page)}`);
}

export async function signInAtMicrosoft(page: Page, user: Credentials, returnOrigin: string): Promise<void> {
  await test.step('Sign in at Microsoft', () => runSignIn(page, user, returnOrigin), { box: true });
}

export async function finishMicrosoftSignOut(page: Page, user: Credentials, returnOrigin: string): Promise<void> {
  await test.step(
    'Finish the Microsoft sign-out',
    async () => {
      const tile = accountTile(page, user);
      const signedOut = shown(page.getByText(/signed out/i));
      await tile
        .or(signedOut)
        .first()
        .waitFor({ state: 'visible', timeout: 30_000 })
        .catch(() => undefined);
      if (await tile.isVisible()) await tile.click();
      await Promise.race([
        signedOut.waitFor({ state: 'visible', timeout: 30_000 }),
        page.waitForURL((url) => url.origin === returnOrigin, { timeout: 30_000 }),
      ]);
    },
    { box: true },
  );
}
