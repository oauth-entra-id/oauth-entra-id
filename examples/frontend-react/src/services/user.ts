import { z } from 'zod';
import { axiosFetch } from '~/lib/axios';
import { zStr } from '~/lib/zod';
import { type Color, useServerStore } from '~/stores/server-store';

const zGetUserData = z.object({
  user: z.object({
    azureId: z.uuid(),
    tenantId: z.uuid(),
    uniqueId: z.uuid(),
    name: zStr,
    email: z.email({ pattern: z.regexes.html5Email }),
    injectedData: z.object({ randomNumber: z.number() }).optional(),
  }),
});

export async function getUserData() {
  const serverUrl = useServerStore.getState().serverUrl;
  const res = await axiosFetch.get(`${serverUrl}/protected/user-info`);
  const parsed = zGetUserData.safeParse(res?.data);
  if (parsed.error) throw new Error('Invalid user data');
  return parsed.data.user;
}

const zGetAUthUrl = z.object({
  url: z.url(),
});

export async function getAuthUrl({
  email,
  loginPrompt,
  azureId,
}: {
  email?: string;
  loginPrompt?: string;
  azureId?: string;
}) {
  const serverUrl = useServerStore.getState().serverUrl;
  const res = await axiosFetch.post(`${serverUrl}/auth/authenticate`, { email, loginPrompt, azureId });
  const parsed = zGetAUthUrl.safeParse(res?.data);
  if (parsed.error) throw new Error('Invalid auth url');
  return parsed.data.url;
}

const zGetLogoutUrl = z.object({
  url: z.url(),
});

export async function logoutAndGetLogoutUrl(params?: { azureId?: string }) {
  const serverUrl = useServerStore.getState().serverUrl;
  const res = await axiosFetch.post(`${serverUrl}/auth/logout`, { azureId: params?.azureId });
  const parsed = zGetLogoutUrl.safeParse(res?.data);
  if (parsed.error) throw new Error('Invalid logout url');
  return parsed.data.url;
}

const zGetTokensOnBehalfOf = z.object({
  tokensSet: z.number(),
});

export async function getTokensOnBehalfOf(params: { serviceNames: Color[]; azureId?: string }) {
  if (!params.serviceNames || params.serviceNames.length === 0) throw new Error('No client IDs provided');
  const serverUrl = useServerStore.getState().serverUrl;
  const res = await axiosFetch.post(`${serverUrl}/protected/on-behalf-of`, {
    services: params.serviceNames,
    azureId: params.azureId,
  });
  const parsed = zGetTokensOnBehalfOf.safeParse(res?.data);
  if (parsed.error) throw new Error('Invalid on-behalf-of tokens');
  return parsed.data.tokensSet;
}
