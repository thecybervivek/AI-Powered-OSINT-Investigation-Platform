import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { AuthProvider } from "@/contexts/AuthContext";
import { ToastProvider } from "@/contexts/ToastContext";
import { LoginPage } from "@/pages/auth/LoginPage";
import { authService } from "@/services/authService";

vi.mock("@/services/authService", () => ({
  authService: {
    login: vi.fn(),
    getCurrentUser: vi.fn(),
    register: vi.fn(),
    logout: vi.fn(),
    isAuthenticated: vi.fn(() => false),
  },
}));

function renderLoginPage() {
  return render(
    <MemoryRouter initialEntries={["/login"]}>
      <ToastProvider>
        <AuthProvider>
          <LoginPage />
        </AuthProvider>
      </ToastProvider>
    </MemoryRouter>
  );
}

describe("LoginPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("shows validation errors when submitted empty", async () => {
    const user = userEvent.setup();
    renderLoginPage();

    await user.click(screen.getByRole("button", { name: /sign in/i }));

    expect(await screen.findByText("Username is required")).toBeInTheDocument();
    expect(await screen.findByText("Password is required")).toBeInTheDocument();
    expect(authService.login).not.toHaveBeenCalled();
  });

  it("calls authService.login with entered credentials on valid submit", async () => {
    const user = userEvent.setup();

    vi.mocked(authService.login).mockResolvedValue({
      access_token: "fake-access",
      refresh_token: "fake-refresh",
      token_type: "bearer",
    });
    vi.mocked(authService.getCurrentUser).mockResolvedValue({
      id: "1",
      email: "alice@example.com",
      username: "alice",
      full_name: "Alice Example",
      role: "user",
      is_active: true,
      is_verified: true,
      is_superuser: false,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    });

    renderLoginPage();

    await user.type(screen.getByLabelText(/username/i), "alice");
    await user.type(screen.getByLabelText(/password/i), "secretpass");
    await user.click(screen.getByRole("button", { name: /sign in/i }));

    await waitFor(() => {
      expect(authService.login).toHaveBeenCalledWith({
        username: "alice",
        password: "secretpass",
      });
    });
  });

  it("shows a server error message on invalid credentials", async () => {
    const user = userEvent.setup();

    vi.mocked(authService.login).mockRejectedValue({
      isAxiosError: true,
      response: { status: 401 },
    });

    renderLoginPage();

    await user.type(screen.getByLabelText(/username/i), "alice");
    await user.type(screen.getByLabelText(/password/i), "wrongpass");
    await user.click(screen.getByRole("button", { name: /sign in/i }));

    expect(
      await screen.findByText("Invalid username or password.")
    ).toBeInTheDocument();
  });
});
