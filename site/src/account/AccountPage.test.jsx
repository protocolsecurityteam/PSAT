import { describe, it, expect, vi } from "vitest";
import { render, screen, waitFor, fireEvent, act } from "@testing-library/react";

import AccountPage from "./AccountPage.jsx";
import SignInModal from "./SignInModal.jsx";
import { setFetchHandler } from "../test/fetchMock.js";

const USER = { id: "u1", email: "alice@example.com", display_name: "Alice", avatar_url: null, is_admin: false };
const HOOK = { id: "w1", label: "ops", discord_webhook_url: "https://discord.com/api/webhooks/1/<redacted>" };

function signedIn() {
  setFetchHandler("/api/me", (url) => {
    if (url.pathname === "/api/me") return USER;
    return null;
  });
}

describe("AccountPage", () => {
  it("asks a signed-out visitor to sign in and shows the provider's error", async () => {
    setFetchHandler("/api/me", () => new Response("{}", { status: 401, headers: { "Content-Type": "application/json" } }));
    window.history.pushState({}, "", "/account?auth_error=Your%20GitHub%20account%20needs%20a%20verified%20primary%20email");
    const onAuth = vi.fn();
    window.addEventListener("psat:auth-required", onAuth);
    render(<AccountPage />);
    expect(await screen.findByText("Sign in to manage alerts")).toBeInTheDocument();
    expect(screen.getByRole("alert")).toHaveTextContent("verified primary email");
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(onAuth).toHaveBeenCalled();
    window.removeEventListener("psat:auth-required", onAuth);
    window.history.pushState({}, "", "/");
  });

  it("lists, saves and deletes webhooks for a signed-in user", async () => {
    let hooks = [HOOK];
    const posted = [];
    signedIn();
    setFetchHandler("/api/me/subscriptions", () => [
      { id: "s1", protocol_id: 7, protocol_name: "etherfi", webhook_id: "w1", event_filter: null },
    ]);
    setFetchHandler("/api/me/webhooks", (url, init) => {
      if (init?.method === "POST") {
        const body = JSON.parse(init.body);
        posted.push(body);
        const hook = { id: "w2", label: body.label, discord_webhook_url: "https://discord.com/api/webhooks/2/<redacted>" };
        hooks = [...hooks, hook];
        return new Response(JSON.stringify(hook), { status: 201, headers: { "Content-Type": "application/json" } });
      }
      if (init?.method === "DELETE") {
        hooks = hooks.filter((h) => !url.pathname.endsWith(h.id));
        return { status: "removed" };
      }
      return hooks;
    });

    render(<AccountPage />);
    expect(await screen.findByRole("heading", { name: "Alice" })).toBeInTheDocument();
    expect(await screen.findByText("→ ops")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "etherfi" })).toBeInTheDocument();
    expect(screen.getByText("All events")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("tab", { name: /Webhooks/ }));
    expect(await screen.findByText("ops")).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText("Discord webhook URL"), {
      target: { value: "https://discord.com/api/webhooks/2/abc" },
    });
    fireEvent.change(screen.getByLabelText("Webhook label"), { target: { value: "alerts" } });
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Save webhook" }));
    });
    expect(posted).toEqual([{ discord_webhook_url: "https://discord.com/api/webhooks/2/abc", label: "alerts" }]);
    expect(await screen.findByText("alerts")).toBeInTheDocument();

    vi.spyOn(window, "confirm").mockReturnValue(true);
    await act(async () => {
      fireEvent.click(screen.getAllByRole("button", { name: "Delete" })[0]);
    });
    await waitFor(() => expect(screen.queryByText("ops")).toBeNull());
  });
});

describe("SignInModal", () => {
  it("links each enabled provider back to the current page", async () => {
    window.history.pushState({}, "", "/company/etherfi/surface");
    setFetchHandler("/api/auth/providers", () => ({
      providers: [{ name: "github", label: "GitHub" }, { name: "google", label: "Google" }],
      dev_login: false,
    }));
    render(<SignInModal onClose={() => {}} />);
    const github = await screen.findByRole("link", { name: "Continue with GitHub" });
    expect(github).toHaveAttribute("href", "/api/auth/github/login?next=%2Fcompany%2Fetherfi%2Fsurface");
    expect(screen.getByRole("link", { name: "Continue with Google" })).toBeInTheDocument();
    expect(screen.queryByLabelText("Dev login email")).toBeNull();
    window.history.pushState({}, "", "/");
  });

  it("offers dev login only when the server enables it", async () => {
    const posted = [];
    setFetchHandler("/api/auth/providers", () => ({ providers: [], dev_login: true }));
    setFetchHandler("/api/auth/dev-login", (url, init) => {
      posted.push(JSON.parse(init.body));
      return { status: "signed_in" };
    });
    const onClose = vi.fn();
    render(<SignInModal onClose={onClose} />);
    fireEvent.change(await screen.findByLabelText("Dev login email"), { target: { value: "dev@example.com" } });
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Dev sign-in" }));
    });
    expect(posted).toEqual([{ email: "dev@example.com" }]);
    await waitFor(() => expect(onClose).toHaveBeenCalled());
  });
});
