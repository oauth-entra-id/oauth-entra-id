export function debugLog({ condition, funcName, message }: { condition: boolean; funcName: string; message: string }) {
  if (condition) {
    console.log(`[oauth-entra-id] ${funcName}: ${message}`);
  }
}
