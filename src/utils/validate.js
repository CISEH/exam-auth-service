import { z } from 'zod';
import { badRequest } from './httpError.js';

/** Parse `data` with a zod schema or throw a 400 with field-level details. */
export function validate(schema, data) {
  const result = schema.safeParse(data ?? {});
  if (!result.success) {
    throw badRequest('Validation failed', result.error.issues.map((i) => ({
      field: i.path.join('.') || undefined,
      message: i.message,
    })));
  }
  return result.data;
}

export { z };
