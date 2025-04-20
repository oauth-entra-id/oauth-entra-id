export const jwtRegex: RegExp = /^[A-Za-z0-9_-]+?\.[A-Za-z0-9_-]+?\.[A-Za-z0-9_-]+?$/;
export const base64urlWithDotRegex: RegExp = /^[A-Za-z0-9._-]+$/;
export const encryptedRegex: RegExp = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.$/;

export const isEncrypted = (str: string) => encryptedRegex.test(str);
export const isJwt = (str: string) => jwtRegex.test(str);
