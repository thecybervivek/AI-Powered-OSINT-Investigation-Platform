import { useState } from "react";
import { Moon, Sun, User as UserIcon } from "lucide-react";
import { useAuth } from "@/contexts/AuthContext";
import { useTheme } from "@/contexts/ThemeContext";
import { useToast } from "@/contexts/ToastContext";
import { Card } from "@/components/Card";
import { Button } from "@/components/Button";
import { Breadcrumbs } from "@/components/Breadcrumbs";
import { formatDate } from "@/utils/formatters";

export function ProfilePage() {
  const { user } = useAuth();
  const { theme, toggleTheme } = useTheme();
  const { showToast } = useToast();

  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);

  async function handleChangePassword(event: React.FormEvent) {
    event.preventDefault();
    setIsSubmitting(true);

    // The backend does not yet expose a change-password endpoint, so
    // this form is intentionally presentational rather than calling a
    // route that doesn't exist.
    await new Promise((resolve) => setTimeout(resolve, 400));

    showToast(
      "info",
      "Password changes aren't available yet — this will be enabled once the backend supports it."
    );
    setCurrentPassword("");
    setNewPassword("");
    setIsSubmitting(false);
  }

  if (!user) return null;

  return (
    <div className="max-w-2xl space-y-6">
      <Breadcrumbs items={[{ label: "Dashboard", to: "/dashboard" }, { label: "Profile" }]} />

      <h1 className="text-2xl font-semibold text-slate-900 dark:text-white">Profile</h1>

      <Card>
        <div className="mb-4 flex items-center gap-4">
          <div className="flex h-14 w-14 items-center justify-center rounded-full bg-brand-600 text-lg font-semibold text-white">
            {user.full_name.charAt(0).toUpperCase()}
          </div>
          <div>
            <p className="font-semibold text-slate-900 dark:text-white">
              {user.full_name}
            </p>
            <p className="text-sm text-slate-500 dark:text-slate-400">
              @{user.username}
            </p>
          </div>
        </div>

        <dl className="grid grid-cols-1 gap-3 text-sm sm:grid-cols-2">
          <div>
            <dt className="text-slate-500 dark:text-slate-400">Email</dt>
            <dd className="font-medium text-slate-900 dark:text-white">{user.email}</dd>
          </div>
          <div>
            <dt className="text-slate-500 dark:text-slate-400">Role</dt>
            <dd className="font-medium capitalize text-slate-900 dark:text-white">
              {user.role}
            </dd>
          </div>
          <div>
            <dt className="text-slate-500 dark:text-slate-400">Account Created</dt>
            <dd className="font-medium text-slate-900 dark:text-white">
              {formatDate(user.created_at)}
            </dd>
          </div>
          <div>
            <dt className="text-slate-500 dark:text-slate-400">Status</dt>
            <dd className="font-medium text-slate-900 dark:text-white">
              {user.is_active ? "Active" : "Inactive"}
            </dd>
          </div>
        </dl>
      </Card>

      <Card>
        <h2 className="mb-3 flex items-center gap-2 font-semibold text-slate-900 dark:text-white">
          <UserIcon className="h-4 w-4" />
          Appearance
        </h2>
        <div className="flex items-center justify-between">
          <p className="text-sm text-slate-600 dark:text-slate-400">
            Switch between light and dark mode.
          </p>
          <Button variant="secondary" onClick={toggleTheme}>
            {theme === "dark" ? (
              <>
                <Sun className="h-4 w-4" /> Switch to Light
              </>
            ) : (
              <>
                <Moon className="h-4 w-4" /> Switch to Dark
              </>
            )}
          </Button>
        </div>
      </Card>

      <Card>
        <h2 className="mb-3 font-semibold text-slate-900 dark:text-white">
          Change Password
        </h2>
        <form onSubmit={handleChangePassword} className="space-y-4">
          <div>
            <label className="mb-1 block text-sm font-medium text-slate-700 dark:text-slate-300">
              Current Password
            </label>
            <input
              type="password"
              value={currentPassword}
              onChange={(event) => setCurrentPassword(event.target.value)}
              className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm focus:border-brand-500 focus:outline-none focus:ring-1 focus:ring-brand-500 dark:border-slate-700 dark:bg-slate-800 dark:text-white"
              required
            />
          </div>
          <div>
            <label className="mb-1 block text-sm font-medium text-slate-700 dark:text-slate-300">
              New Password
            </label>
            <input
              type="password"
              value={newPassword}
              onChange={(event) => setNewPassword(event.target.value)}
              minLength={8}
              className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm focus:border-brand-500 focus:outline-none focus:ring-1 focus:ring-brand-500 dark:border-slate-700 dark:bg-slate-800 dark:text-white"
              required
            />
          </div>
          <Button type="submit" isLoading={isSubmitting}>
            Update Password
          </Button>
        </form>
      </Card>
    </div>
  );
}
