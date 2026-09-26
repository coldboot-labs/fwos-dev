import { readFileSync } from "node:fs";

let browser;
let stage = "input";
let result = { ok: false, stage };
try {
  const { url, action, username, password } = JSON.parse(readFileSync(0, "utf8"));
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
  await page.goto(url);
  await page.getByLabel("Username", { exact: true }).fill(username);
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await page.getByRole("heading", { name: "Status", exact: true }).waitFor();
  await page.getByRole("heading", { name: "Apply confirmation", exact: true }).waitFor();
  stage = action;
  if (action === "enable") {
    await page.locator("#apply-confirmation-status").getByText("Disabled:", { exact: false }).waitFor();
    await page.getByLabel("Require confirmation after Apply").check();
    await page.getByRole("button", { name: "Apply setting", exact: true }).click();
    await page.locator("#apply-confirmation-result").getByText("Setting accepted", { exact: false }).waitFor({ timeout: 60_000 });
    await page.locator("#apply-confirmation-status").getByText("Enabled:", { exact: false }).waitFor();
  } else if (action === "disable") {
    await page.locator("#apply-confirmation-status").getByText("Enabled:", { exact: false }).waitFor();
    await page.getByLabel("Require confirmation after Apply").uncheck();
    await page.getByRole("button", { name: "Apply setting", exact: true }).click();
    await page.locator("#apply-confirmation-result").getByText("pending confirmation", { exact: false }).waitFor({ timeout: 60_000 });
    await page.locator("#pending-apply-status").getByText("Pending revision", { exact: false }).waitFor();
  } else if (action === "confirm" || action === "confirm-setting") {
    await page.locator("#pending-apply-status").getByText("Pending revision", { exact: false }).waitFor();
    const pendingText = await page.locator("#pending-apply-status").textContent();
    const revision = pendingText?.match(/Pending revision (\d+)/)?.[1];
    if (!revision) throw new Error("pending revision is not visible");
    const status = await page.evaluate(async () => (await fetch("/api/apply-confirmation")).json());
    const confirmationId = status.pending?.confirmation_id;
    if (!confirmationId || String(status.pending.revision) !== revision) {
      throw new Error("pending review is not bound to a confirmation operation");
    }
    await page.getByRole("button", { name: "Review pending revision", exact: true }).click();
    const review = page.locator("#pending-apply-review");
    await review.getByRole("heading", { name: `Review applied revision ${revision}`, exact: true }).waitFor();
    const details = await review.textContent();
    const expectedSetting = action === "confirm-setting"
      ? "Apply confirmation setting: enabled → disabled"
      : "Apply confirmation setting: enabled → enabled";
    const expectedRoutes = action === "confirm-setting" ? "Routes: [{" : "Routes: [] →";
    if (!details?.includes(`Confirmation ID: ${confirmationId}`) ||
        !details?.includes(expectedSetting) ||
        !details?.includes(expectedRoutes) ||
        !details?.includes("198.51.100.0/24") ||
        !details?.includes("Applied by alice")) {
      throw new Error("pending review omitted revision changes or applying administrator");
    }
    await review.getByRole("button", { name: "Confirm reviewed revision", exact: true }).click();
    await page.locator("#apply-confirmation-result").getByText("Accepted revision", { exact: false }).waitFor({ timeout: 60_000 });
  } else {
    throw new Error("unsupported Apply confirmation action");
  }
  result = { ok: true };
} catch (error) {
  result = { ok: false, stage, error: String(error?.message || error).slice(0, 400) };
} finally {
  await browser?.close().catch(() => {});
}
process.stdout.write(`${JSON.stringify(result)}\n`);
process.exitCode = result.ok ? 0 : 1;
