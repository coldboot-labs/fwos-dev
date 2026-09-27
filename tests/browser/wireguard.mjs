import { readFileSync } from "node:fs";

let browser;
let stage = "input";
let result = { ok: false, stage };
try {
  const input = JSON.parse(readFileSync(0, "utf8"));
  const { firefox } = await import("playwright-core");
  stage = "launch";
  browser = await firefox.launch({
    channel: "moz-firefox",
    executablePath: process.env.FWOS_FIREFOX_PATH || "/usr/bin/firefox",
    headless: true,
    timeout: 30_000,
  });
  const page = await browser.newPage({ ignoreHTTPSErrors: true });
  page.setDefaultTimeout(20_000);
  stage = "sign-in";
  await page.goto(input.url);
  await page.getByLabel("Username", { exact: true }).fill(input.username);
  await page.getByLabel("Password", { exact: true }).fill(input.password);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await page.getByRole("heading", { name: "Status", exact: true }).waitFor();
  const wireguard = page.locator("section").filter({
    has: page.getByRole("heading", { name: "WireGuard", exact: true }),
  });
  await page.locator("#accepted-wireguard-status").getByText("Accepted revision", { exact: false }).waitFor();
  stage = "edit";
  if (input.name != null) await wireguard.locator("#wireguard-name").fill(input.name);
  if (input.privateKey != null) await wireguard.locator("#wireguard-key").fill(input.privateKey);
  if (input.listenPort != null) await wireguard.locator("#wireguard-port").fill(String(input.listenPort));
  if (input.addresses != null) await wireguard.locator("#wireguard-addresses").fill(input.addresses);
  if (input.routeTo != null) await wireguard.locator("#wireguard-route-to").fill(input.routeTo);
  if (input.routeVia != null) await wireguard.locator("#wireguard-route-via").fill(input.routeVia);
  const action = input.action || "apply";
  if (action === "save-and-apply") {
    stage = "shortcut";
    await wireguard.getByRole("button", { name: "Save and apply WireGuard", exact: true }).click();
  } else if (action === "apply-draft") {
    stage = "draft-review";
    await page.getByRole("button", { name: "Review pending draft", exact: true }).click();
    const review = await page.locator("#draft-review-summary").textContent();
    if (!review?.includes("private key set") || (input.privateKey && review.includes(input.privateKey))) {
      throw new Error("draft review reveals a WireGuard private key or omits the tunnel");
    }
    stage = "draft-apply";
    await page.getByRole("button", { name: "Apply reviewed draft", exact: true }).click();
  } else {
    stage = "review";
    await wireguard.getByRole("button", { name: "Review WireGuard", exact: true }).click();
    await wireguard.getByRole("heading", { name: "Review WireGuard", exact: true }).waitFor();
    const summary = await wireguard.locator("#wireguard-summary").textContent();
    if (!summary?.includes("Accepted revision") || (input.privateKey && summary.includes(input.privateKey))) {
      throw new Error("WireGuard review reveals the private key or omits the revision");
    }
    if (action === "save-draft") {
      stage = "save-draft";
      await wireguard.getByRole("button", { name: "Save WireGuard draft", exact: true }).click();
    } else {
      stage = "apply";
      await wireguard.getByRole("button", { name: "Apply WireGuard", exact: true }).click();
    }
  }
  const expected = action === "reject" ? "Rejected:"
    : action === "save-draft" ? "networking unchanged"
      : action === "failed" ? /Apply failed|Rejected:/
        : "Accepted revision";
  stage = "result";
  await page.locator("#wireguard-result, #route-result").getByText(expected, { exact: false }).waitFor({
    timeout: action === "failed" ? 180_000 : 90_000,
  });
  const body = await page.locator("body").innerText();
  if (input.privateKey && body.includes(input.privateKey)) {
    throw new Error("rendered status shows a WireGuard private key");
  }
  result = { ok: true };
} catch (error) {
  const message = error instanceof Error ? error.message : "WireGuard editor failed";
  result = { ok: false, stage, error: message.slice(0, 180) };
} finally {
  if (browser) await browser.close();
  process.stdout.write(JSON.stringify(result));
  if (!result.ok) process.exitCode = 1;
}
