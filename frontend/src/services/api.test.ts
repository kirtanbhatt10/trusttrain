import { describe, expect, it, vi } from "vitest";
import { mockFetch } from "../test/mockApi";
import { ApiError, api, getToken, setToken, setUnauthorizedHandler } from "./api";

describe("api client", () => {
  it("sends the bearer token and parses JSON", async () => {
    const { calls } = mockFetch({ "GET /api/datasets": [] });
    setToken("abc");
    await expect(api.datasets()).resolves.toEqual([]);
    expect(new Headers(calls[0].init.headers).get("Authorization")).toBe("Bearer abc");
    expect(sessionStorage.getItem("trusttrain.token")).toBe("abc");
    setToken(null);
    expect(getToken()).toBeNull();
  });

  it("builds filter query strings and drops empty values", async () => {
    const { fn } = mockFetch({ "GET /api/findings": [] });
    await api.findings({ severity: "high", method: "", status: undefined });
    expect(String(fn.mock.calls[0][0])).toBe("/api/findings?severity=high");
  });

  it("raises ApiError with the server detail", async () => {
    mockFetch({ "POST /api/datasets/x/inspect": new Response(JSON.stringify({ detail: "Column 'nope' not present" }), { status: 422, headers: { "content-type": "application/json" } }) });
    await expect(api.inspect("x", { label_column: "nope" })).rejects.toMatchObject({ status: 422, message: "Column 'nope' not present" });
  });

  it("joins validation error lists", async () => {
    mockFetch({ "POST /api/incidents": new Response(JSON.stringify({ detail: [{ msg: "too short" }, { msg: "bad severity" }] }), { status: 422 }) });
    await expect(api.createIncident({ title: "x" })).rejects.toThrow("too short; bad severity");
  });

  it("calls the unauthorized handler on 401", async () => {
    const handler = vi.fn();
    setUnauthorizedHandler(handler);
    mockFetch({ "GET /api/auth/me": new Response(JSON.stringify({ detail: "Not authenticated" }), { status: 401 }) });
    await expect(api.me()).rejects.toBeInstanceOf(ApiError);
    expect(handler).toHaveBeenCalledOnce();
    setUnauthorizedHandler(null);
  });

  it("reports network failures", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("Failed to fetch")));
    await expect(api.summary()).rejects.toMatchObject({ status: 0, message: "Cannot reach the TrustTrain API" });
  });

  it("returns text for markdown reports and sends JSON bodies", async () => {
    const { calls } = mockFetch({ "GET /api/incidents/inc-1/report": "# Incident report", "POST /api/incidents/inc-1/transition": {} });
    await expect(api.incidentReportMarkdown("inc-1")).resolves.toBe("# Incident report");
    await api.transitionIncident("inc-1", "resolved", "done");
    expect(JSON.parse(String(calls[1].init.body))).toEqual({ state: "resolved", comment: "done" });
    expect(new Headers(calls[1].init.headers).get("Content-Type")).toBe("application/json");
  });
});
