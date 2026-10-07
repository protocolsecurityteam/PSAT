import { describe, it, expect } from "vitest";

import { streamAgentChat } from "./agent.js";
import { setFetchHandler } from "../test/fetchMock.js";

describe("agent chat auth", () => {
  it("opens sign-in on a 401 instead of prompting for a key", async () => {
    setFetchHandler("/api/agent/chat", () => new Response("", { status: 401 }));
    let asked = 0;
    const onAuth = () => { asked += 1; };
    window.addEventListener("psat:auth-required", onAuth);
    try {
      await expect(streamAgentChat({ message: "hi" }, () => {})).rejects.toThrow("401");
    } finally {
      window.removeEventListener("psat:auth-required", onAuth);
    }
    expect(asked).toBe(1);
  });
});
