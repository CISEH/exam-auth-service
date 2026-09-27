export class HttpError extends Error {
  constructor(status, message, details) {
    super(message);
    this.status = status;
    this.details = details;
  }
}

export const badRequest = (msg = 'Bad request', details) => new HttpError(400, msg, details);
export const unauthorized = (msg = 'Authentication required') => new HttpError(401, msg);
export const forbidden = (msg = 'You do not have permission to perform this action') => new HttpError(403, msg);
export const notFound = (msg = 'Resource not found') => new HttpError(404, msg);
export const conflict = (msg = 'Conflict', details) => new HttpError(409, msg, details);
export const unprocessable = (msg = 'Unprocessable request', details) => new HttpError(422, msg, details);
