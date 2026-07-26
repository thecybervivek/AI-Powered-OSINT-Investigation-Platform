import { describe, expect, it } from "vitest";
import { loginSchema, registerSchema } from "@/utils/validation";

describe("loginSchema", () => {
  it("accepts valid credentials", () => {
    const result = loginSchema.safeParse({ username: "alice", password: "secret" });
    expect(result.success).toBe(true);
  });

  it("rejects an empty username", () => {
    const result = loginSchema.safeParse({ username: "", password: "secret" });
    expect(result.success).toBe(false);
  });

  it("rejects an empty password", () => {
    const result = loginSchema.safeParse({ username: "alice", password: "" });
    expect(result.success).toBe(false);
  });
});

describe("registerSchema", () => {
  const validPayload = {
    full_name: "Alice Example",
    username: "alice",
    email: "alice@example.com",
    password: "SuperSecret123",
  };

  it("accepts a fully valid registration payload", () => {
    expect(registerSchema.safeParse(validPayload).success).toBe(true);
  });

  it("rejects an invalid email", () => {
    const result = registerSchema.safeParse({ ...validPayload, email: "not-an-email" });
    expect(result.success).toBe(false);
  });

  it("rejects a password shorter than 8 characters", () => {
    const result = registerSchema.safeParse({ ...validPayload, password: "short" });
    expect(result.success).toBe(false);
  });

  it("rejects a username shorter than 3 characters", () => {
    const result = registerSchema.safeParse({ ...validPayload, username: "ab" });
    expect(result.success).toBe(false);
  });
});
