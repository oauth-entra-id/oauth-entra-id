import { z } from 'zod';

export const zStr = z.string().trim().min(1);

export const zUrl = zStr.url();

export const zEmailForm = z.object({ email: zStr.email().max(128) });
