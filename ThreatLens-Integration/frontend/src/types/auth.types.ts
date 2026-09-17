/**
 * The four platform roles.
 *
 * These strings must match, verbatim:
 *   - UserRole in backend/app/schemas/user_schema.py (what /auth/login puts
 *     in the JWT `role` claim)
 *   - the role sets in backend/app/alerts/router.py
 *   - ROLES / ROLE_LABELS / PAGE_ACCESS in src/constants/roles.ts
 *
 * This declaration previously read "admin" | "analyst" | "viewer" while
 * roles.ts and data/userData.ts had already moved to the names below, so
 * `npm run build` failed with 24 TS2322 errors. src/constants/roles.ts
 * derives its Role type from here, which makes this the frontend's single
 * source of truth for the vocabulary.
 */
export type Role =
  | "security_analyst"
  | "soc_team_member"
  | "administrator"
  | "researcher";

export interface User {
  id: string;
  name: string;
  email: string;
  role: Role;
  avatarUrl?: string;
}

export interface LoginCredentials {
  email: string;
  password: string;
  rememberMe?: boolean;
}

export interface AuthResponse {
  user: User;
  token: string;
}
