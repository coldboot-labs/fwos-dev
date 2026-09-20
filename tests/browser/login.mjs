import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

// Credentials arrive over stdin, never argv. Playwright debug logging can include
// form values, so disable it before loading the driver and never print raw errors.
delete process.env.DEBUG;
delete process.env.PWDEBUG;

let browser;
let stage = "input";
let result;
let timedOut = false;

const deadline = setTimeout(() => {
  timedOut = true;
  process.stdout.write(`${JSON.stringify({ ok: false, scenario: "local-identity", stage })}\n`);
  // Close the isolated browser first, but keep a hard bound if it is unresponsive.
  setTimeout(() => process.exit(1), 5_000);
  Promise.resolve(browser?.close()).then(
    () => process.exit(1),
    () => process.exit(1),
  );
}, 120_000);

try {
  const { url, username, password } = JSON.parse(readFileSync(0, "utf8"));
  const target = new URL(url);
  assert.equal(target.protocol, "https:");
  assert.ok(["127.0.0.1", "[::1]"].includes(target.hostname));
  assert.equal(target.username, "");
  assert.equal(target.password, "");
  assert.equal(typeof username, "string");
  assert.equal(typeof password, "string");
  assert.ok(username.length > 0 && password.length > 0);

  stage = "launch";
  const { firefox } = await import("playwright-core");
  browser = await firefox.launch({
    channel: "moz-firefox",
    executablePath: process.env.FWOS_FIREFOX_PATH || "/usr/bin/firefox",
    headless: true,
    timeout: 30_000,
  });
  // Each launch uses a temporary profile: no personal browser state or session.
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const page = await context.newPage();
  page.setDefaultTimeout(20_000);
  page.setDefaultNavigationTimeout(30_000);

  stage = "unauthenticated";
  await page.goto(target.href);
  const signIn = page.getByRole("heading", { name: "Sign in", exact: true });
  const status = page.getByRole("heading", { name: "Status", exact: true });
  await signIn.waitFor();
  assert.equal(await status.isVisible(), false);

  stage = "wrong-password";
  await page.getByLabel("Username", { exact: true }).fill(username);
  await page.getByLabel("Password", { exact: true }).fill(`${password}-incorrect`);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await page.getByText("login failed", { exact: true }).waitFor();
  assert.ok(await signIn.isVisible());
  assert.equal(await status.isVisible(), false);

  stage = "sign-in";
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await status.waitFor();
  await page.getByText(`Signed in as ${username} (local)`, { exact: true }).waitFor();
  await page.getByText("hostname: fwos-box", { exact: true }).waitFor();

  stage = "authenticated-reload";
  await page.reload();
  await status.waitFor();
  await page.getByText("hostname: fwos-box", { exact: true }).waitFor();

  stage = "sign-out";
  await page.getByRole("button", { name: "Sign out", exact: true }).click();
  await signIn.waitFor();
  assert.equal(await status.isVisible(), false);

  stage = "signed-out-reload";
  await page.reload();
  await signIn.waitFor();
  assert.equal(await status.isVisible(), false);
  result = { ok: true, scenario: "local-identity", browser: browser.version() };
} catch {
  // Stages are fixed identifiers, not UI text, request bodies, or credential data.
  result = { ok: false, scenario: "local-identity", stage };
} finally {
  try {
    await browser?.close();
  } catch {
    result = { ok: false, scenario: "local-identity", stage: "close" };
  }
  clearTimeout(deadline);
}

if (!timedOut) {
  process.stdout.write(`${JSON.stringify(result)}\n`);
  process.exitCode = result.ok ? 0 : 1;
}
