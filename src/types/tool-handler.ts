import { z } from 'zod';

export const USER_ID_ARG = 'user_id';

export const UserIdParameter = z.object({
  user_id: z.string().email().describe('Email address of the Google account to use (e.g., "josh@omaihq.com")')
});

export interface AccountInfo {
  email: string;
  accountType: string;
  extraInfo?: string;
  gauthFile?: string;

  toDescription(): string;
}
