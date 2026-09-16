import { AuthResponse, LoginCredentials, User } from "@/types/auth.types";
import axiosInstance from "./axiosInstance";

/** UserResponse as returned by /api/v1/auth (backend/app/schemas/user_schema.py). */
interface UserResponse {
  id: number;
  full_name: string;
  email: string;
  role: User["role"];
  is_active: boolean;
}

function toUser(u: UserResponse): User {
  return {
    id: String(u.id),
    name: u.full_name,
    email: u.email,
    role: u.role,
  };
}

export const authApi = {
  login: async (credentials: LoginCredentials): Promise<AuthResponse> => {
    // /auth/login is an OAuth2 password flow: form-encoded, and the email
    // travels in the field OAuth2 calls "username".
    const form = new URLSearchParams();
    form.append("username", credentials.email);
    form.append("password", credentials.password);

    const { data } = await axiosInstance.post<{ access_token: string }>(
      "/auth/login",
      form,
      { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
    );

    const token = data.access_token;

    // The token carries only `sub` and `role`; the profile endpoint has the
    // rest. Passed explicitly because the interceptor reads from storage,
    // which the caller has not written yet.
    const { data: profile } = await axiosInstance.get<UserResponse>("/auth/profile", {
      headers: { Authorization: `Bearer ${token}` },
    });

    return { user: toUser(profile), token };
  },

  register: async (payload: {
    full_name: string;
    email: string;
    password: string;
    role: User["role"];
  }): Promise<User> => {
    const { data } = await axiosInstance.post<UserResponse>("/auth/register", payload);
    return toUser(data);
  },

  /**
   * JWTs are stateless and the backend exposes no revocation endpoint, so
   * signing out is purely client-side: the slice clears the stored token.
   * Kept as a function so the slice keeps one call site if that changes.
   */
  logout: async (): Promise<void> => {
    return;
  },

  getProfile: async (): Promise<User> => {
    const { data } = await axiosInstance.get<UserResponse>("/auth/profile");
    return toUser(data);
  },

  updateProfile: async (changes: { full_name?: string; email?: string }): Promise<User> => {
    const { data } = await axiosInstance.put<UserResponse>("/auth/profile", changes);
    return toUser(data);
  },
};
