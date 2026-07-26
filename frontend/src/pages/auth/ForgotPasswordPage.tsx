import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { Link } from "react-router-dom";
import { useState } from "react";
import { Button } from "@/components/Button";
import {
  forgotPasswordSchema,
  type ForgotPasswordFormValues,
} from "@/utils/validation";

export function ForgotPasswordPage() {
  const [submitted, setSubmitted] = useState(false);

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<ForgotPasswordFormValues>({
    resolver: zodResolver(forgotPasswordSchema),
  });

  async function onSubmit() {
    // The backend does not yet expose a password-reset endpoint. This
    // screen is intentionally presentational until one is added, rather
    // than silently calling a route that doesn't exist.
    await new Promise((resolve) => setTimeout(resolve, 400));
    setSubmitted(true);
  }

  if (submitted) {
    return (
      <div className="text-center">
        <h2 className="mb-2 text-xl font-semibold text-slate-900 dark:text-white">
          Check your email
        </h2>
        <p className="text-sm text-slate-500 dark:text-slate-400">
          If an account exists for that address, password reset instructions
          will be sent once this feature is enabled on the server.
        </p>
        <Link
          to="/login"
          className="mt-6 inline-block text-sm text-brand-600 hover:underline"
        >
          Back to sign in
        </Link>
      </div>
    );
  }

  return (
    <div>
      <h2 className="mb-2 text-xl font-semibold text-slate-900 dark:text-white">
        Reset your password
      </h2>
      <p className="mb-6 text-sm text-slate-500 dark:text-slate-400">
        Enter your email and we'll send you instructions to reset your
        password.
      </p>

      <form onSubmit={handleSubmit(onSubmit)} className="space-y-4" noValidate>
        <div>
          <label
            htmlFor="email"
            className="mb-1 block text-sm font-medium text-slate-700 dark:text-slate-300"
          >
            Email
          </label>
          <input
            id="email"
            type="email"
            className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm focus:border-brand-500 focus:outline-none focus:ring-1 focus:ring-brand-500 dark:border-slate-700 dark:bg-slate-800 dark:text-white"
            {...register("email")}
          />
          {errors.email && (
            <p className="mt-1 text-xs text-red-600">{errors.email.message}</p>
          )}
        </div>

        <Button type="submit" isLoading={isSubmitting} className="w-full">
          Send Reset Instructions
        </Button>
      </form>

      <Link
        to="/login"
        className="mt-4 inline-block text-sm text-brand-600 hover:underline"
      >
        Back to sign in
      </Link>
    </div>
  );
}
