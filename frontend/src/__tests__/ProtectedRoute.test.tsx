import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import { AuthProvider } from "@/contexts/AuthContext";
import { ProtectedRoute } from "@/components/ProtectedRoute";

vi.mock("@/services/authService", () => ({
  authService: {
    login: vi.fn(),
    getCurrentUser: vi.fn(),
    register: vi.fn(),
    logout: vi.fn(),
    isAuthenticated: vi.fn(() => false),
  },
}));

vi.mock("@/services/apiClient", () => ({
  tokenStorage: {
    getAccessToken: vi.fn(() => null),
    setTokens: vi.fn(),
    setAccessToken: vi.fn(),
    clear: vi.fn(),
  },
  apiClient: { post: vi.fn().mockRejectedValue(new Error("no session")) },
}));

describe("ProtectedRoute", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("redirects to /login when no access token is present", async () => {
    render(
      <MemoryRouter initialEntries={["/dashboard"]}>
        <AuthProvider>
          <Routes>
            <Route path="/login" element={<div>Login Page</div>} />
            <Route element={<ProtectedRoute />}>
              <Route path="/dashboard" element={<div>Dashboard Page</div>} />
            </Route>
          </Routes>
        </AuthProvider>
      </MemoryRouter>
    );

    expect(await screen.findByText("Login Page")).toBeInTheDocument();
  });
});
