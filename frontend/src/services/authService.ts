import { apiClient, tokenStorage } from "./apiClient";
import type {
  LoginRequest,
  RegisterRequest,
  TokenResponse,
  User,
} from "@/types/auth";

export const authService = {
  async login(credentials: LoginRequest): Promise<TokenResponse> {
    const form = new URLSearchParams();
    form.append("username", credentials.username);
    form.append("password", credentials.password);

    const response = await apiClient.post<TokenResponse>("/login", form, {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
    });

    tokenStorage.setTokens(
      response.data.access_token,
      response.data.refresh_token
    );

    return response.data;
  },

  async register(payload: RegisterRequest): Promise<User> {
    const response = await apiClient.post<User>("/register", payload);
    return response.data;
  },

  async getCurrentUser(): Promise<User> {
    const response = await apiClient.get<User>("/me");
    return response.data;
  },

  async logout(): Promise<void> {
    try {
      await apiClient.post("/logout");
    } finally {
      tokenStorage.clear();
    }
  },

  isAuthenticated(): boolean {
    return Boolean(tokenStorage.getAccessToken());
  },
};
