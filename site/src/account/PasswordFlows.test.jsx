import { describe, it, expect, vi } from "vitest";
import { render, screen, waitFor, fireEvent, act } from "@testing-library/react";

import AccountPage from "./AccountPage.jsx";
import SetPasswordPage from "./SetPasswordPage.jsx";
import SignInModal from "./SignInModal.jsx";
import { setFetchHandler } from "../test/fetchMock.js";

function recordPosts(path, respond = () => ({})) {
  const posted = [];
  setFetchHandler(
    (url, init) => url.pathname === path && init?.method === "POST",
    (url, init) => {
      posted.push(JSON.parse(init.body));
      return respond(posted.at(-1));
    },
  );
  return posted;
}

function passwordProviders() {
  setFetchHandler("/api/auth/providers", () => ({
    providers: [{ name: "github", label: "GitHub" }],
    dev_login: false,
    password: true,
  }));
}

describe("SignInModal — email and password", () => {
  it("signs in with email and password", async () => {
    passwordProviders();
    const posted = recordPosts("/api/auth/password/login");
    const onClose = vi.fn();
    render(<SignInModal onClose={onClose} />);
    fireEvent.change(await screen.findByLabelText("Email"), { target: { value: "alice@example.com" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "hunter2hunter2" } });
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
    });
    expect(posted).toEqual([{ email: "alice@example.com", password: "hunter2hunter2" }]);
    await waitFor(() => expect(onClose).toHaveBeenCalled());
  });

  it("shows the server's error on a bad password", async () => {
    passwordProviders();
    setFetchHandler("/api/auth/password/login", () =>
      new Response(JSON.stringify({ detail: "Incorrect email or password" }), {
        status: 401,
        headers: { "Content-Type": "application/json" },
      }));
    render(<SignInModal onClose={() => {}} />);
    fireEvent.change(await screen.findByLabelText("Email"), { target: { value: "a@example.com" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "wrong" } });
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
    });
    expect(await screen.findByRole("alert")).toHaveTextContent("Incorrect email or password");
  });

  it("creates an account with only an email, then says to check the inbox", async () => {
    passwordProviders();
    const posted = recordPosts("/api/auth/register", () => ({ status: "check_email" }));
    render(<SignInModal onClose={() => {}} />);
    fireEvent.click(await screen.findByRole("button", { name: "Create an account" }));
    // Sign-up never asks for a password; the emailed link does.
    expect(screen.queryByLabelText("Password")).toBeNull();
    fireEvent.change(screen.getByLabelText("Email"), { target: { value: "new@example.com" } });
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Email me a sign-up link" }));
    });
    expect(posted).toEqual([{ email: "new@example.com" }]);
    expect(await screen.findByRole("status")).toHaveTextContent("Check new@example.com");
  });

  it("requests a reset link", async () => {
    passwordProviders();
    const posted = recordPosts("/api/auth/password/forgot", () => ({ status: "check_email" }));
    render(<SignInModal onClose={() => {}} />);
    fireEvent.click(await screen.findByRole("button", { name: "Forgot password?" }));
    fireEvent.change(screen.getByLabelText("Email"), { target: { value: "alice@example.com" } });
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Email me a reset link" }));
    });
    expect(posted).toEqual([{ email: "alice@example.com" }]);
  });

  it("hides the password form when the server can't send email", async () => {
    setFetchHandler("/api/auth/providers", () => ({ providers: [{ name: "github", label: "GitHub" }], password: false }));
    render(<SignInModal onClose={() => {}} />);
    await screen.findByRole("link", { name: "Continue with GitHub" });
    expect(screen.queryByLabelText("Email")).toBeNull();
  });
});

describe("SetPasswordPage", () => {
  it("posts the link's token, then strips it from the address bar", async () => {
    window.history.pushState({}, "", "/set-password?token=tok-123");
    const posted = recordPosts("/api/auth/password/set", () => ({ status: "signed_in" }));
    const onDone = vi.fn();
    render(<SetPasswordPage onDone={onDone} />);
    expect(window.location.search).toBe("");

    fireEvent.change(screen.getByLabelText("New password"), { target: { value: "long enough pw" } });
    fireEvent.change(screen.getByLabelText("Confirm new password"), { target: { value: "different pw!!" } });
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Set password" }));
    });
    expect(screen.getByRole("alert")).toHaveTextContent("don't match");
    expect(posted).toEqual([]);

    fireEvent.change(screen.getByLabelText("Confirm new password"), { target: { value: "long enough pw" } });
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Set password" }));
    });
    expect(posted).toEqual([{ token: "tok-123", password: "long enough pw" }]);
    await waitFor(() => expect(onDone).toHaveBeenCalled());
    window.history.pushState({}, "", "/");
  });

  it("explains an expired link", async () => {
    window.history.pushState({}, "", "/set-password?token=old");
    setFetchHandler("/api/auth/password/set", () =>
      new Response(JSON.stringify({ detail: "This link is invalid or has expired; request a new one" }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      }));
    render(<SetPasswordPage />);
    fireEvent.change(screen.getByLabelText("New password"), { target: { value: "long enough pw" } });
    fireEvent.change(screen.getByLabelText("Confirm new password"), { target: { value: "long enough pw" } });
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Set password" }));
    });
    expect(await screen.findByRole("alert")).toHaveTextContent("expired");
    window.history.pushState({}, "", "/");
  });
});

describe("AccountPage — password", () => {
  function signedIn(hasPassword) {
    setFetchHandler("/api/me", (url) =>
      url.pathname === "/api/me"
        ? { id: "u1", email: "alice@example.com", display_name: "Alice", is_admin: false, has_password: hasPassword }
        : []);
  }

  it("asks for the current password before changing it", async () => {
    signedIn(true);
    const posted = recordPosts("/api/me/password", () => ({ status: "password_set" }));
    render(<AccountPage />);
    fireEvent.change(await screen.findByLabelText("Current password"), { target: { value: "old password!" } });
    fireEvent.change(screen.getByLabelText("New password"), { target: { value: "new password!!" } });
    fireEvent.change(screen.getByLabelText("Confirm new password"), { target: { value: "new password!!" } });
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Change password" }));
    });
    expect(posted).toEqual([{ current_password: "old password!", new_password: "new password!!" }]);
    expect(await screen.findByText("Password saved.")).toBeInTheDocument();
  });

  it("lets a provider-only account add a password without a current one", async () => {
    signedIn(false);
    const posted = recordPosts("/api/me/password", () => ({ status: "password_set" }));
    render(<AccountPage />);
    await screen.findByRole("button", { name: "Add password" });
    expect(screen.queryByLabelText("Current password")).toBeNull();
    fireEvent.change(screen.getByLabelText("New password"), { target: { value: "new password!!" } });
    fireEvent.change(screen.getByLabelText("Confirm new password"), { target: { value: "new password!!" } });
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Add password" }));
    });
    expect(posted).toEqual([{ current_password: null, new_password: "new password!!" }]);
  });
});
