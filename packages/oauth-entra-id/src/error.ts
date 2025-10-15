import { ZodError } from 'zod';
import { $isPlainObj } from './utils/zod';

export type HttpErrorCodes = 400 | 401 | 403 | 500;

export interface ErrorStruct {
  readonly message: string;
  readonly description: string;
  readonly statusCode: HttpErrorCodes;
}

type ReservedWords<Obj extends object> = 'success' extends keyof Obj ? never : 'error' extends keyof Obj ? never : Obj;

type OkType<T> = {
  readonly success: true;
  readonly error?: undefined;
} & (T extends object ? ReservedWords<{ readonly [K in keyof T]: T[K] }> : { readonly result: T });

type ErrType<T> = {
  readonly success: false;
  readonly error: ErrorStruct;
} & (T extends object ? ReservedWords<{ readonly [K in keyof T]?: undefined }> : { readonly result?: undefined });

export type Result<T> = OkType<T> | ErrType<T>;

export function $ok<T>(result?: T): Result<T> {
  if ($isPlainObj(result)) return { success: true, ...(result as object) } as Result<T>;
  return { success: true, result } as Result<T>;
}

interface ShortErrorStruct {
  readonly msg: string;
  readonly desc: string;
  readonly status?: HttpErrorCodes;
}

export function $err(err: ShortErrorStruct | ErrorStruct | OAuthError | Result<never>): Result<never> {
  if (err instanceof OAuthError) {
    return {
      success: false,
      error: { message: err.message, description: err.description, statusCode: err.statusCode },
    } as Result<never>;
  }

  if ('success' in err) {
    if (err.success === true || !('error' in err)) {
      throw new Error('Cannot create an error Result from a success Result');
    }
    return err as Result<never>;
  }

  return {
    success: false,
    error: {
      message: 'msg' in err ? err.msg : err.message,
      description: 'desc' in err ? err.desc : err.description,
      statusCode: 'status' in err ? (err.status ?? 400) : (err as ErrorStruct).statusCode,
    },
  } as Result<never>;
}

/**
 * Custom error class for handling OAuth-related errors.
 *
 * This error is designed for use in OAuth authentication flows,
 * providing an HTTP status code, a message, and an optional description.
 *
 * @extends {Error}
 */
export class OAuthError extends Error {
  readonly statusCode: HttpErrorCodes;
  readonly description: string;

  constructor(err: ShortErrorStruct | ErrorStruct | Result<never>) {
    if ('success' in err) {
      if (err.success === true || !('error' in err)) {
        throw new Error('Cannot create an error Result from a success Result');
      }
      const error = err.error as ErrorStruct;
      super(error.message);
      this.description = error.description;
      this.statusCode = error.statusCode;
    } else {
      super('msg' in err ? err.msg : (err.message ?? 'Unknown Error'));
      this.description = 'desc' in err ? err.desc : (err.description ?? 'An unknown error occurred');
      this.statusCode = 'status' in err ? (err.status ?? 500) : (err as ErrorStruct).statusCode;
    }

    this.name = 'OAuthError';

    Object.setPrototypeOf(this, new.target.prototype);
    if (Error.captureStackTrace) Error.captureStackTrace(this, this.constructor);
  }
}

export function $fmtError(err: unknown): string {
  if (typeof err === 'string') {
    return `error (string): ${err}`;
  }
  if (err instanceof OAuthError) {
    return `error (OAuthError): ${err.message} (${err.statusCode}) - ${err.description}`;
  }
  if (err instanceof ZodError) {
    return `error (ZodError - Schema Validation): ${err.issues
      .map((issue) => `${issue.path.length > 0 ? issue.path.join('.') : 'root'}: ${issue.message}`)
      .join('. ')}`;
  }
  if (err instanceof Error) {
    return `error (Error ${err.name}): ${err.message} - ${err.stack ?? 'No stack trace available'}`;
  }
  if (typeof err === 'object' && err !== null) {
    switch (true) {
      case 'message' in err && 'description' in err && 'statusCode' in err: {
        return `error (ErrorStruct): ${err.message} (${err.statusCode}) - ${err.description}`;
      }
      case 'msg' in err && 'desc' in err: {
        return `error (ShortErrorStruct): ${err.msg} (${(err as ShortErrorStruct).status ?? 500}) - ${err.desc}`;
      }
      default: {
        try {
          return `error (Object): ${JSON.stringify(err)}`;
        } catch (error) {
          return `error (Object): Failed to stringify error object - ${String(error)}`;
        }
      }
    }
  }
  return `error (Unknown): ${String(err)}`;
}
