import type { WebApiKey } from 'cipher-kit';
import { compressObj, decompressObj } from 'compress-kit';
import type { z } from 'zod';
import { $err, $ok, $stringErr, type Result } from '~/error';
import type { CryptoType, EncryptionKey } from '~/types';
import { $decrypt, $decryptObj, $encrypt, $encryptObj } from './encrypt';
import { $getClientId } from './jwt';
import { zAtStruct, zEncrypted, zInjectedData, zJwt, zLooseBase64, zRtStruct, zState, zUuid } from './zod';

type BaseParams = {
  key: EncryptionKey;
  cryptoType: CryptoType;
  $updateSecretKey: UpdateSecretKeyFunc;
};

type UpdateSecretKeyFunc = (
  key: 'accessToken' | 'refreshToken' | 'state' | 'ticket',
  secretKey: WebApiKey | undefined,
) => void;

export async function $encryptAccessToken<T extends object = Record<string, any>>(
  value: string | null,
  params: BaseParams & {
    expiry: number;
    azureId: string;
    isOtherKey: boolean;
    disableCompression?: boolean;
    dataToInject?: T;
  },
): Promise<Result<{ encrypted: string }>> {
  const { data: accessToken, error: jwtError } = zJwt.safeParse(value);
  if (jwtError) return $err({ msg: 'Invalid access token format', desc: $stringErr(jwtError) });

  const { data: dataToInject, error: injectError } = zInjectedData.safeParse(params.dataToInject);
  if (injectError) return $err({ msg: 'Invalid injected data format', desc: $stringErr(injectError) });

  const injectedData =
    dataToInject && Object.keys(dataToInject).length !== 0 && !params.disableCompression
      ? compressObj(dataToInject)
      : undefined;

  if (injectedData?.error) {
    return $err({ msg: 'Failed to compress injected data', desc: `Compression - ${$stringErr(injectedData.error)}` });
  }

  const struct = {
    at: accessToken,
    inj: injectedData?.result,
    exp: Date.now() + params.expiry * 1000,
    aid: params.azureId,
  } satisfies z.infer<typeof zAtStruct>;

  const { encrypted, newSecretKey, error } = await $encryptObj(params.cryptoType, struct, params.key);
  if (error) return $err({ msg: 'Failed to encrypt access token', desc: `Encryption - ${$stringErr(error)}` });

  if (params.isOtherKey === false) params.$updateSecretKey('accessToken', newSecretKey);

  if (encrypted.length > 4096) {
    return $err({
      msg: 'Token too long',
      desc: `Encrypted access token exceeds 4096 characters. Encrypted length: ${encrypted.length}, original length: ${accessToken.length}, injected data length: ${injectedData?.result.length ?? 0}`,
    });
  }

  return $ok({ encrypted: encrypted });
}

export async function $decryptAccessToken<T extends object = Record<string, any>>(
  value: string | undefined,
  params: BaseParams,
): Promise<Result<{ decrypted: string; azureId: string; injectedData?: T; wasEncrypted: boolean }>> {
  const { data: jwtToken, success: jwtSuccess } = zJwt.safeParse(value);
  if (jwtSuccess) {
    const { clientId, error: jwtError } = $getClientId(jwtToken);
    if (jwtError) return $err(jwtError);
    return $ok({ decrypted: jwtToken, azureId: clientId, injectedData: undefined, wasEncrypted: false });
  }

  const { data: encryptedAt, error: encryptedAtError } = zEncrypted.safeParse(value);
  if (encryptedAtError) return $err({ msg: 'Unauthorized', desc: $stringErr(encryptedAtError) });

  const { result, newSecretKey, error } = await $decryptObj(params.cryptoType, encryptedAt, params.key);
  if (error) return $err({ msg: 'Failed to decrypt access token', desc: `Decryption - ${$stringErr(error)}` });

  params.$updateSecretKey('accessToken', newSecretKey);

  const { data: atStruct, error: atStructError } = zAtStruct.safeParse(result);
  if (atStructError) return $err({ msg: 'Invalid access token format', desc: $stringErr(atStructError) });

  if (atStruct.exp < Date.now()) {
    return $err({
      msg: 'Access token expired',
      desc: `Access token expired at ${new Date(atStruct.exp).toISOString()}`,
    });
  }

  const decompressedInjectedData = atStruct.inj ? decompressObj(atStruct.inj) : undefined;
  if (decompressedInjectedData?.error) {
    return $err({
      msg: 'Failed to decompress injected data',
      desc: `Decompression - ${$stringErr(decompressedInjectedData.error)}`,
    });
  }

  return $ok({
    decrypted: atStruct.at,
    azureId: atStruct.aid,
    injectedData: decompressedInjectedData ? (decompressedInjectedData.result as T) : undefined,
    wasEncrypted: true,
  });
}

export async function $encryptRefreshToken(
  value: string | null,
  params: BaseParams & { expiry: number; azureId: string },
): Promise<Result<{ encrypted: string }>> {
  const { data, error: parseError } = zLooseBase64.safeParse(value);
  if (parseError) return $err({ msg: 'Invalid refresh token format', desc: $stringErr(parseError) });

  const struct = {
    rt: data,
    exp: Date.now() + params.expiry * 1000,
    aid: params.azureId,
  } satisfies z.infer<typeof zRtStruct>;

  const { encrypted, newSecretKey, error } = await $encryptObj(params.cryptoType, struct, params.key);
  if (error) return $err({ msg: 'Failed to encrypt refresh token', desc: `Encryption - ${$stringErr(error)}` });

  params.$updateSecretKey('refreshToken', newSecretKey);

  if (encrypted.length > 4096) {
    return $err({
      msg: 'Invalid format',
      desc: `Encrypted refresh token exceeds 4096 characters. Encrypted length: ${encrypted.length}, original length: ${data.length}`,
    });
  }

  return $ok({ encrypted: encrypted });
}

export async function $decryptRefreshToken(
  value: string | undefined,
  params: BaseParams,
): Promise<Result<{ decrypted: string; azureId: string }>> {
  const { data: encryptedRefreshToken, error: encryptedRefreshTokenError } = zEncrypted.safeParse(value);
  if (encryptedRefreshTokenError) return $err({ msg: 'Invalid format', desc: $stringErr(encryptedRefreshTokenError) });

  const { result, newSecretKey, error } = await $decryptObj(params.cryptoType, encryptedRefreshToken, params.key);
  if (error) return $err({ msg: 'Failed to decrypt refresh token', desc: `Decryption - ${$stringErr(error)}` });

  const { data: rtStruct, error: rtStructError } = zRtStruct.safeParse(result);
  if (rtStructError) return $err({ msg: 'Invalid format', desc: $stringErr(rtStructError) });

  if (rtStruct.exp < Date.now()) {
    return $err({ msg: 'Invalid Params', desc: `Refresh token expired at ${new Date(rtStruct.exp).toISOString()}` });
  }

  params.$updateSecretKey('refreshToken', newSecretKey);

  return $ok({ decrypted: rtStruct.rt, azureId: rtStruct.aid });
}

export async function $encryptState(value: object | null, params: BaseParams): Promise<Result<{ encrypted: string }>> {
  const { data, error: parseError } = zState.safeParse(value);
  if (parseError) return $err({ msg: 'Invalid format', desc: $stringErr(parseError) });

  const { encrypted, newSecretKey, error } = await $encryptObj(params.cryptoType, data, params.key);
  if (error) return $err({ msg: 'Failed to encrypt state', desc: `Encryption - ${$stringErr(error)}` });

  params.$updateSecretKey('state', newSecretKey);

  return $ok({ encrypted: encrypted });
}

export async function $decryptState(
  value: string | undefined,
  params: BaseParams,
): Promise<Result<{ decrypted: z.infer<typeof zState> }>> {
  const { data: encryptedState, error: encryptedStateError } = zEncrypted.safeParse(value);
  if (encryptedStateError) return $err({ msg: 'Invalid format', desc: $stringErr(encryptedStateError) });

  const { result, newSecretKey, error } = await $decryptObj(params.cryptoType, encryptedState, params.key);
  if (error) return $err({ msg: 'Failed to decrypt state', desc: $stringErr(error) });

  params.$updateSecretKey('state', newSecretKey);

  const { data: state, error: stateError } = zState.safeParse(result);
  if (stateError) return $err({ msg: 'Invalid format', desc: $stringErr(stateError) });

  return $ok({ decrypted: state });
}

export async function $encryptTicket(
  ticketId: string | null,
  params: BaseParams,
): Promise<Result<{ encrypted: string }>> {
  const { data, error: parseError } = zUuid.safeParse(ticketId);
  if (parseError) return $err({ msg: 'Invalid format', desc: $stringErr(parseError) });

  const { encrypted, newSecretKey, error } = await $encrypt(params.cryptoType, data, params.key);
  if (error) return $err({ msg: 'Failed to encrypt ticket', desc: `Encryption - ${$stringErr(error)}` });

  params.$updateSecretKey('ticket', newSecretKey);
  return $ok({ encrypted: encrypted });
}

export async function $decryptTicket(
  value: string | undefined,
  params: BaseParams,
): Promise<Result<{ decrypted: string }>> {
  const { data, error: encryptedStateError } = zEncrypted.safeParse(value);
  if (encryptedStateError) return $err({ msg: 'Invalid format', desc: $stringErr(encryptedStateError) });

  const { result, newSecretKey, error } = await $decrypt(params.cryptoType, data, params.key);
  if (error) return $err({ msg: 'Failed to decrypt ticket', desc: `Decryption - ${$stringErr(error)}` });

  params.$updateSecretKey('ticket', newSecretKey);

  const { data: ticketId, error: stateError } = zUuid.safeParse(result);
  if (stateError) return $err({ msg: 'Invalid format', desc: $stringErr(stateError) });

  return $ok({ decrypted: ticketId });
}
