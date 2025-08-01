import type { z } from 'zod/v4';
import { $err, $ok, type Result } from '~/error';
import type { CryptoType, EncryptionKey, WebApiCryptoKey } from '~/types';
import {
  $prettyErr,
  zAccessTokenStructure,
  zEncrypted,
  zInjectedData,
  zJwt,
  zLooseBase64,
  zRefreshTokenStructure,
  zState,
  zUuid,
} from '../zod';
import { $compressObj, $decompressObj } from './compress';
import { $decrypt, $decryptObj, $encrypt, $encryptObj } from './encrypt';
import { $getClientId } from './jwt';

type BaseParams = {
  key: EncryptionKey;
  cryptoType: CryptoType;
  $updateSecretKey: UpdateSecretKeyFunc;
};

type UpdateSecretKeyFunc = (
  key: 'accessToken' | 'refreshToken' | 'state' | 'ticket',
  secretKey: WebApiCryptoKey | undefined,
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
  if (jwtError) {
    return $err('invalid_format', { error: 'Invalid access token format', description: $prettyErr(jwtError) });
  }

  const { data: dataToInject, error: injectError } = zInjectedData.safeParse(params.dataToInject);
  if (injectError) {
    return $err('invalid_format', { error: 'Invalid injected data format', description: $prettyErr(injectError) });
  }

  const injectedData =
    dataToInject && Object.keys(dataToInject).length
      ? $compressObj(dataToInject, params?.disableCompression)
      : undefined;

  if (injectedData?.error) return $err(injectedData.error);

  const struct = {
    at: accessToken,
    inj: injectedData?.result,
    exp: Date.now() + params.expiry * 1000,
    aid: params.azureId,
  } satisfies z.infer<typeof zAccessTokenStructure>;

  const { encrypted, newSecretKey, error } = await $encryptObj(params.cryptoType, struct, params.key);
  if (error) {
    return $err('crypto_error', { error: 'Failed to encrypt access token', description: error.description });
  }

  if (params.isOtherKey === false) params.$updateSecretKey('accessToken', newSecretKey);

  if (encrypted.length > 4096) {
    return $err('invalid_format', {
      error: 'Token too long',
      description: `Encrypted access token exceeds 4096 characters. Encrypted length: ${encrypted.length}, original length: ${accessToken.length}, injected data length: ${injectedData?.result.length ?? 0}`,
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

  const { data: encryptedAccessToken, error: encryptedAccessTokenError } = zEncrypted.safeParse(value);
  if (encryptedAccessTokenError) {
    return $err('invalid_format', { error: 'Unauthorized', description: 'Invalid access token format' });
  }

  const { result, newSecretKey, error } = await $decryptObj(params.cryptoType, encryptedAccessToken, params.key);
  if (error) {
    return $err('crypto_error', { error: 'Failed to decrypt access token', description: error.description });
  }

  params.$updateSecretKey('accessToken', newSecretKey);

  const { data: accessTokenStruct, error: accessTokenStructError } = zAccessTokenStructure.safeParse(result);
  if (accessTokenStructError) {
    return $err('invalid_format', {
      error: 'Invalid access token format',
      description: $prettyErr(accessTokenStructError),
    });
  }

  if (accessTokenStruct.exp < Date.now()) {
    return $err('bad_request', {
      error: 'Access token expired',
      description: `Access token expired at ${new Date(accessTokenStruct.exp).toISOString()}`,
    });
  }

  const decompressedInjectedData = accessTokenStruct.inj ? $decompressObj(accessTokenStruct.inj) : undefined;
  if (decompressedInjectedData?.error) return $err(decompressedInjectedData.error);

  return $ok({
    decrypted: accessTokenStruct.at,
    azureId: accessTokenStruct.aid,
    injectedData: decompressedInjectedData ? (decompressedInjectedData.result as T) : undefined,
    wasEncrypted: true,
  });
}

export async function $encryptRefreshToken(
  value: string | null,
  params: BaseParams & { expiry: number; azureId: string },
): Promise<Result<{ encrypted: string }>> {
  const { data, error: parseError } = zLooseBase64.safeParse(value);
  if (parseError) {
    return $err('invalid_format', { error: 'Invalid refresh token format', description: $prettyErr(parseError) });
  }

  const { encrypted, newSecretKey, error } = await $encryptObj(
    params.cryptoType,
    {
      rt: data,
      exp: Date.now() + params.expiry * 1000,
      aid: params.azureId,
    } satisfies z.infer<typeof zRefreshTokenStructure>,
    params.key,
  );
  if (error) {
    return $err('crypto_error', { error: 'Failed to encrypt refresh token', description: error.description });
  }

  params.$updateSecretKey('refreshToken', newSecretKey);

  if (encrypted.length > 4096) {
    return $err('invalid_format', {
      error: 'Token too long',
      description: `Encrypted refresh token exceeds 4096 characters. Encrypted length: ${encrypted.length}, original length: ${data.length}`,
    });
  }

  return $ok({ encrypted: encrypted });
}

export async function $decryptRefreshToken(
  value: string | undefined,
  params: BaseParams,
): Promise<Result<{ decrypted: string; azureId: string }>> {
  const { data: encryptedRefreshToken, error: encryptedRefreshTokenError } = zEncrypted.safeParse(value);
  if (encryptedRefreshTokenError) {
    return $err('invalid_format', { error: 'Unauthorized', description: 'Invalid refresh token format' });
  }

  const { result, newSecretKey, error } = await $decryptObj(params.cryptoType, encryptedRefreshToken, params.key);
  if (error) {
    return $err('crypto_error', { error: 'Failed to decrypt refresh token', description: error.description });
  }

  const { data: refreshTokenStruct, error: refreshTokenStructError } = zRefreshTokenStructure.safeParse(result);
  if (refreshTokenStructError) {
    return $err('invalid_format', {
      error: 'Invalid refresh token format',
      description: $prettyErr(refreshTokenStructError),
    });
  }

  if (refreshTokenStruct.exp < Date.now()) {
    return $err('bad_request', {
      error: 'Refresh token expired',
      description: `Refresh token expired at ${new Date(refreshTokenStruct.exp).toISOString()}`,
    });
  }

  params.$updateSecretKey('refreshToken', newSecretKey);

  return $ok({ decrypted: refreshTokenStruct.rt, azureId: refreshTokenStruct.aid });
}

export async function $encryptState(value: object | null, params: BaseParams): Promise<Result<{ encrypted: string }>> {
  const { data, error: parseError } = zState.safeParse(value);
  if (parseError) {
    return $err('invalid_format', { error: 'Invalid state format', description: $prettyErr(parseError) });
  }

  const { encrypted, newSecretKey, error } = await $encryptObj(params.cryptoType, data, params.key);
  if (error) {
    return $err('crypto_error', { error: 'Failed to encrypt state', description: error.description });
  }

  params.$updateSecretKey('state', newSecretKey);

  return $ok({ encrypted: encrypted });
}

export async function $decryptState(
  value: string | undefined,
  params: BaseParams,
): Promise<Result<{ decrypted: z.infer<typeof zState> }>> {
  const { data: encryptedState, error: encryptedStateError } = zEncrypted.safeParse(value);
  if (encryptedStateError) {
    return $err('invalid_format', { error: 'Invalid state format', description: $prettyErr(encryptedStateError) });
  }

  const { result, newSecretKey, error } = await $decryptObj(params.cryptoType, encryptedState, params.key);
  if (error) {
    return $err('crypto_error', { error: 'Failed to decrypt state', description: error.description });
  }

  params.$updateSecretKey('state', newSecretKey);

  const { data: state, error: stateError } = zState.safeParse(result);
  if (stateError) {
    return $err('invalid_format', { error: 'Invalid state format', description: $prettyErr(stateError) });
  }

  return $ok({ decrypted: state });
}

export async function $encryptTicket(
  ticketId: string | null,
  params: BaseParams,
): Promise<Result<{ encrypted: string }>> {
  const { data, error: parseError } = zUuid.safeParse(ticketId);
  if (parseError) {
    return $err('invalid_format', { error: 'Invalid ticket format', description: $prettyErr(parseError) });
  }

  const { encrypted, newSecretKey, error } = await $encrypt(params.cryptoType, data, params.key);
  if (error) {
    return $err('crypto_error', { error: 'Failed to encrypt ticket', description: error.description });
  }

  params.$updateSecretKey('ticket', newSecretKey);

  return $ok({ encrypted: encrypted });
}

export async function $decryptTicket(
  value: string | undefined,
  params: BaseParams,
): Promise<Result<{ decrypted: string }>> {
  const { data, error: encryptedStateError } = zEncrypted.safeParse(value);
  if (encryptedStateError) {
    return $err('invalid_format', { error: 'Invalid ticket format', description: $prettyErr(encryptedStateError) });
  }

  const { result, newSecretKey, error } = await $decrypt(params.cryptoType, data, params.key);
  if (error) {
    return $err('crypto_error', { error: 'Failed to decrypt ticket', description: error.description });
  }

  params.$updateSecretKey('ticket', newSecretKey);

  const { data: ticketId, error: stateError } = zUuid.safeParse(result);
  if (stateError) {
    return $err('invalid_format', { error: 'Invalid state format', description: $prettyErr(stateError) });
  }

  return $ok({ decrypted: ticketId });
}
