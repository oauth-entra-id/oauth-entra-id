import { z } from 'zod/v4';

export const zStr = z.string().trim().min(1);

export const zUrl = z.url();

export const zEmailForm = z.object({ email: z.email({ pattern: z.regexes.html5Email }).max(128) });
