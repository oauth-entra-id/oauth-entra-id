import { serverNames, servers } from '../src/env';
import { expect, test } from '../src/fixtures';
import { looksLikeJwt } from '../src/mobile-api-client';

for (const server of serverNames) {
  test(`${servers[server].label}: the session survives reloads and refreshes through the refresh token, and tampered tokens end it`, async ({
    phone,
    mobileApi,
  }) => {
    const device = await phone.signedIn(server);
    const api = mobileApi(server);

    await test.step('reloading keeps me signed in as the same account', async () => {
      const before = await device.app.profile();
      await device.app.reload();
      await device.app.expectConnected();
      const after = await device.app.profile();
      expect(after.uniqueId).toBe(before.uniqueId);
      expect(after.email).toBe(before.email);
    });

    await test.step('a corrupted access token is replaced through my refresh token', async () => {
      const before = await device.app.storedTokens();
      await device.app.corruptAccessToken();
      await device.app.reload();
      await device.app.expectConnected();

      const after = await device.app.storedTokens();
      expect(after?.accessToken).not.toBe('tampered');
      expect(after?.accessToken).not.toBe(before?.accessToken);
      expect(after?.refreshToken).not.toBe(before?.refreshToken);
      expect(looksLikeJwt(after?.accessToken ?? ''), 'the new access token is a plain JWT').toBe(false);
      expect((await api.userInfo(after?.accessToken)).status(), 'the new access token works').toBe(200);
    });

    await test.step('tampered tokens end my session', async () => {
      await device.app.corruptAccessToken();
      await device.app.corruptRefreshToken();
      await device.app.reload();
      await device.app.expectGuest();
      expect(await device.app.storedTokens()).toBeNull();
      expect((await api.userInfo('tampered')).status()).toBe(401);
    });
  });
}
