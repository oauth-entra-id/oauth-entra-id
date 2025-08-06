import type { WebApiKey } from 'cipher-kit';
import { compressObj, decompressObj } from 'compress-kit';
import type { z } from 'zod/v4';
import { $err, $ok, type Result } from '~/error';
import type { CryptoType, EncryptionKey } from '~/types';
import { $decrypt, $decryptObj, $encrypt, $encryptObj } from './encrypt';
import { $getClientId } from './jwt';
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
} from './zod';

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
  if (jwtError) {
    return $err({ msg: 'Invalid access token format', desc: `Failed schema: ${$prettyErr(jwtError)}` });
  }

  const { data: dataToInject, error: injectError } = zInjectedData.safeParse(params.dataToInject);
  if (injectError) {
    return $err({
      msg: 'Invalid injected data format',
      desc: `Failed zInjectedData schema: ${$prettyErr(injectError)}`,
    });
  }

  const injectedData =
    dataToInject && Object.keys(dataToInject).length !== 0 && !params.disableCompression
      ? compressObj(dataToInject)
      : undefined;

  if (injectedData?.error) {
    return $err({
      msg: 'Failed to compress injected data',
      desc: `Compression error: message: ${injectedData.error.message}, description: ${injectedData.error.description}`,
    });
  }

  const struct = {
    at: accessToken,
    inj: injectedData?.result,
    exp: Date.now() + params.expiry * 1000,
    aid: params.azureId,
  } satisfies z.infer<typeof zAccessTokenStructure>;

  const { encrypted, newSecretKey, error } = await $encryptObj(params.cryptoType, struct, params.key);
  if (error) {
    return $err({
      msg: 'Failed to encrypt access token',
      desc: `Encryption error: message: ${error.message}, description: ${error.description}`,
    });
  }

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

  const { data: encryptedAccessToken, error: encryptedAccessTokenError } = zEncrypted.safeParse(value);
  if (encryptedAccessTokenError) {
    return $err({ msg: 'Unauthorized', desc: `Failed schema: ${$prettyErr(encryptedAccessTokenError)}` });
  }

  const { result, newSecretKey, error } = await $decryptObj(params.cryptoType, encryptedAccessToken, params.key);
  if (error) {
    return $err({
      msg: 'Failed to decrypt access token',
      desc: `Decryption error: message: ${error.message}, description: ${error.description}`,
    });
  }

  params.$updateSecretKey('accessToken', newSecretKey);

  const { data: accessTokenStruct, error: accessTokenStructError } = zAccessTokenStructure.safeParse(result);
  if (accessTokenStructError) {
    return $err({
      msg: 'Invalid access token format',
      desc: `Failed schema: ${$prettyErr(accessTokenStructError)}`,
    });
  }

  if (accessTokenStruct.exp < Date.now()) {
    return $err({
      msg: 'Access token expired',
      desc: `Access token expired at ${new Date(accessTokenStruct.exp).toISOString()}`,
    });
  }

  const decompressedInjectedData = accessTokenStruct.inj ? decompressObj(accessTokenStruct.inj) : undefined;
  if (decompressedInjectedData?.error) {
    return $err({
      msg: 'Failed to decompress injected data',
      desc: `Decompression error: message: ${decompressedInjectedData.error.message}, description: ${decompressedInjectedData.error.description}`,
    });
  }

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
    return $err({ msg: 'Invalid refresh token format', desc: `Failed schema: ${$prettyErr(parseError)}` });
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
    return $err({
      msg: 'Failed to encrypt refresh token',
      desc: `Encryption error: message: ${error.message}, description: ${error.description}`,
    });
  }

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
  if (encryptedRefreshTokenError) {
    return $err({ msg: 'Invalid format', desc: `Failed schema: ${$prettyErr(encryptedRefreshTokenError)}` });
  }

  const { result, newSecretKey, error } = await $decryptObj(params.cryptoType, encryptedRefreshToken, params.key);
  if (error) {
    return $err({
      msg: 'Failed to decrypt refresh token',
      desc: `Decryption error: message: ${error.message}, description: ${error.description}`,
    });
  }

  const { data: refreshTokenStruct, error: refreshTokenStructError } = zRefreshTokenStructure.safeParse(result);
  if (refreshTokenStructError) {
    return $err({ msg: 'Invalid format', desc: `Failed schema: ${$prettyErr(refreshTokenStructError)}` });
  }

  if (refreshTokenStruct.exp < Date.now()) {
    return $err({
      msg: 'Bad request',
      desc: `Refresh token expired at ${new Date(refreshTokenStruct.exp).toISOString()}`,
    });
  }

  params.$updateSecretKey('refreshToken', newSecretKey);

  return $ok({ decrypted: refreshTokenStruct.rt, azureId: refreshTokenStruct.aid });
}

export async function $encryptState(value: object | null, params: BaseParams): Promise<Result<{ encrypted: string }>> {
  const { data, error: parseError } = zState.safeParse(value);
  if (parseError) {
    return $err({ msg: 'Invalid format', desc: `Failed schema: ${$prettyErr(parseError)}` });
  }

  const { encrypted, newSecretKey, error } = await $encryptObj(params.cryptoType, data, params.key);
  if (error) {
    return $err({
      msg: 'Failed to encrypt state',
      desc: `Encryption error: message: ${error.message}, description: ${error.description}`,
    });
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
    return $err({ msg: 'Invalid format', desc: `Failed schema: ${$prettyErr(encryptedStateError)}` });
  }

  const { result, newSecretKey, error } = await $decryptObj(params.cryptoType, encryptedState, params.key);
  if (error) {
    return $err({ msg: 'Failed to decrypt state', desc: error.description });
  }

  params.$updateSecretKey('state', newSecretKey);

  const { data: state, error: stateError } = zState.safeParse(result);
  if (stateError) {
    return $err({ msg: 'Invalid format', desc: `Failed schema: ${$prettyErr(stateError)}` });
  }

  return $ok({ decrypted: state });
}

export async function $encryptTicket(
  ticketId: string | null,
  params: BaseParams,
): Promise<Result<{ encrypted: string }>> {
  const { data, error: parseError } = zUuid.safeParse(ticketId);
  if (parseError) {
    return $err({ msg: 'Invalid format', desc: `Failed schema: ${$prettyErr(parseError)}` });
  }

  const { encrypted, newSecretKey, error } = await $encrypt(params.cryptoType, data, params.key);
  if (error) {
    return $err({
      msg: 'Failed to encrypt ticket',
      desc: `Encryption error: message: ${error.message}, description: ${error.description}`,
    });
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
    return $err({ msg: 'Invalid format', desc: `Failed schema: ${$prettyErr(encryptedStateError)}` });
  }

  const { result, newSecretKey, error } = await $decrypt(params.cryptoType, data, params.key);
  if (error) {
    return $err({
      msg: 'Failed to decrypt ticket',
      desc: `Decryption error: message: ${error.message}, description: ${error.description}`,
    });
  }

  params.$updateSecretKey('ticket', newSecretKey);

  const { data: ticketId, error: stateError } = zUuid.safeParse(result);
  if (stateError) {
    return $err({ msg: 'Invalid format', desc: `Failed schema: ${$prettyErr(stateError)}` });
  }

  return $ok({ decrypted: ticketId });
}
