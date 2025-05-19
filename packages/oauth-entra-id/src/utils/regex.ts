export const base64urlWithDotRegex = /^[A-Za-z0-9._-]+$/;
export const jwtRegex = /^[A-Za-z0-9_-]+?\.[A-Za-z0-9_-]+?\.[A-Za-z0-9_-]+?$/;
export const encryptedRegex = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.$/;
export const jwtOrEncryptedRegex = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.?$/;
export const cookieNameRegex = base64urlWithDotRegex;
export const cookieValueRegex = base64urlWithDotRegex;

export const isEncrypted = (str: string) => encryptedRegex.test(str);
export const isJwt = (str: string) => jwtRegex.test(str);
