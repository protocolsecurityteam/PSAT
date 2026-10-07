import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, fireEvent, act } from "@testing-library/react";

import ResetPasswordPage from "./ResetPasswordPage.jsx";
import SignInModal from "./SignInModal.jsx";
import { setFetchHandler } from "../test/fetchMock.js";
import { resetAuthConfigForTests } from "../api/authConfig.js";
import { resetNeonAuthForTests } from "../api/neonAuth.js";

const neon = vi.hoisted(() => ({
  signIn: { email: vi.fn(), social: vi.fn() },
  signUp: { email: vi.fn() },
  requestPasswordReset: vi.fn(),
  resetPassword: vi.fn(),
}));

vi.mock("@neondatabase/auth", () => ({ createAuthClient: vi.fn(() => neon) }));

function recordPosts(path, respond = () => ({})) {
  const posted = [];
  setFetchHandler(
    (url, init) => url.pathname === path && init?.method === "POST",
    (url) => {
      posted.push(url.search);
      return respond();
    },
  );
  return posted;
}

function neonEnabled() {
  setFetchHandler("/api/auth/config", () => ({ enabled: true, providers: ["github"], dev_login: false }));
}

beforeEach(() => {
  resetNeonAuthForTests();
  for (const fn of [neon.signIn.email, neon.signIn.social, neon.signUp.email, neon.requestPasswordReset, neon.resetPassword]) {
    fn.mockReset().mockResolvedValue({ data: {}, error: null });
  }
});

describe("SignInModal — Neon Auth", () => {
  it("signs in with email and password, then opens our session", async () => {
    neonEnabled();
    const sessions = recordPosts("/api/auth/session", () => ({ status: "signed_in" }));
    const onClose = vi.fn();
    render(<SignInModal onClose={onClose} />);
    fireEvent.change(await screen.findByLabelText("Email"), { target: { value: "alice@example.com" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "hunter2hunter2" } });
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
    });
    expect(neon.signIn.email).toHaveBeenCalledWith({ email: "alice@example.com", password: "hunter2hunter2" });
    expect(sessions).toEqual([""]);
    await waitFor(() => expect(onClose).toHaveBeenCalled());
  });

  it("shows Neon's error and opens no session", async () => {
    neonEnabled();
    neon.signIn.email.mockResolvedValue({ data: null, error: { message: "Invalid email or password" } });
    const sessions = recordPosts("/api/auth/session");
    render(<SignInModal onClose={() => {}} />);
    fireEvent.change(await screen.findByLabelText("Email"), { target: { value: "a@example.com" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "wrong" } });
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
    });
    expect(await screen.findByRole("alert")).toHaveTextContent("Invalid email or password");
    expect(sessions).toEqual([]);
  });

  it("creates an account, then asks to verify the email", async () => {
    neonEnabled();
    render(<SignInModal onClose={() => {}} />);
    fireEvent.click(await screen.findByRole("button", { name: "Create an account" }));
    fireEvent.change(screen.getByLabelText("Email"), { target: { value: "new@example.com" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "long enough" } });
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Create account" }));
    });
    expect(neon.signUp.email).toHaveBeenCalledWith(expect.objectContaining({ email: "new@example.com", name: "new" }));
    expect(await screen.findByRole("status")).toHaveTextContent("Check new@example.com to verify");
  });

  it("requests a reset link back to our reset page", async () => {
    neonEnabled();
    render(<SignInModal onClose={() => {}} />);
    fireEvent.click(await screen.findByRole("button", { name: "Forgot password?" }));
    fireEvent.change(screen.getByLabelText("Email"), { target: { value: "alice@example.com" } });
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Email me a reset link" }));
    });
    expect(neon.requestPasswordReset).toHaveBeenCalledWith({
      email: "alice@example.com",
      redirectTo: `${window.location.origin}/reset-password`,
    });
  });

  it("starts GitHub sign-in through Neon, returning to this page", async () => {
    neonEnabled();
    render(<SignInModal onClose={() => {}} />);
    const github = await screen.findByRole("button", { name: "Continue with GitHub" });
    await act(async () => {
      fireEvent.click(github);
    });
    expect(neon.signIn.social).toHaveBeenCalledWith({ provider: "github", callbackURL: window.location.href });
  });

  it("offers the shared admin key only where the deployment accepts one", async () => {
    setFetchHandler("/api/auth/config", () => ({ enabled: true, providers: [], dev_login: false, admin_key: false }));
    const { unmount } = render(<SignInModal onClose={() => {}} />);
    await screen.findByLabelText("Email");
    expect(screen.queryByRole("button", { name: "Use an admin key instead" })).toBeNull();
    unmount();

    resetAuthConfigForTests();
    setFetchHandler("/api/auth/config", () => ({ enabled: true, providers: [], dev_login: false, admin_key: true }));
    render(<SignInModal onClose={() => {}} />);
    expect(await screen.findByRole("button", { name: "Use an admin key instead" })).toBeInTheDocument();
  });

  it("says so when sign-in isn't configured", async () => {
    setFetchHandler("/api/auth/config", () => ({ enabled: false, providers: [], dev_login: false }));
    render(<SignInModal onClose={() => {}} />);
    expect(await screen.findByText("Sign-in isn't configured on this server.")).toBeInTheDocument();
    expect(screen.queryByLabelText("Email")).toBeNull();
  });
});

describe("ResetPasswordPage", () => {
  it("sets the new password with the link's token, then strips it from the address bar", async () => {
    window.history.pushState({}, "", "/reset-password?token=tok-123");
    render(<ResetPasswordPage />);
    expect(window.location.search).toBe("");

    fireEvent.change(screen.getByLabelText("New password"), { target: { value: "long enough pw" } });
    fireEvent.change(screen.getByLabelText("Confirm new password"), { target: { value: "different pw!!" } });
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Set password" }));
    });
    expect(screen.getByRole("alert")).toHaveTextContent("don't match");
    expect(neon.resetPassword).not.toHaveBeenCalled();

    fireEvent.change(screen.getByLabelText("Confirm new password"), { target: { value: "long enough pw" } });
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Set password" }));
    });
    expect(neon.resetPassword).toHaveBeenCalledWith({ newPassword: "long enough pw", token: "tok-123" });
    expect(await screen.findByRole("status")).toHaveTextContent("Password updated");
    window.history.pushState({}, "", "/");
  });

  it("explains an expired link", () => {
    window.history.pushState({}, "", "/reset-password?error=INVALID_TOKEN");
    render(<ResetPasswordPage />);
    expect(screen.getByRole("alert")).toHaveTextContent("expired");
    window.history.pushState({}, "", "/");
  });
});
