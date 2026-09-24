import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

delete process.env.DEBUG;
delete process.env.PWDEBUG;

let browser;
let stage = "input";
let result;
let timedOut = false;
const deadline = setTimeout(() => {
  timedOut = true;
  process.stdout.write(`${JSON.stringify({ ok: false, scenario: "one-nic-warning", stage })}\n`);
  setTimeout(() => process.exit(1), 5_000);
  Promise.resolve(browser?.close()).then(() => process.exit(1), () => process.exit(1));
}, 120_000);

try {
  const { url } = JSON.parse(readFileSync(0, "utf8"));
  const target = new URL(url);
  assert.equal(target.protocol, "https:");
  assert.ok(["127.0.0.1", "[::1]"].includes(target.hostname));
  assert.equal(target.username, "");
  assert.equal(target.password, "");

  stage = "launch";
  const { firefox } = await import("playwright-core");
  browser = await firefox.launch({
    channel: "moz-firefox",
    executablePath: process.env.FWOS_FIREFOX_PATH || "/usr/bin/firefox",
    headless: true,
    timeout: 30_000,
  });
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const page = await context.newPage();
  page.setDefaultTimeout(20_000);
  page.setDefaultNavigationTimeout(30_000);

  stage = "wizard";
  await page.goto(target.href);
  await page.getByRole("heading", { name: "Bootstrap wizard", exact: true }).waitFor();
  const warning = page.locator("#warn");
  const untaggedWarning = "Untagged first-boot HTTPS will vanish";
  assert.equal(await page.locator("#wan_tagged").isChecked(), false);
  assert.equal(await page.locator("#lan_tagged").isChecked(), true);
  assert.ok((await warning.textContent()).includes(untaggedWarning));
  assert.ok((await warning.textContent()).includes("Apply still proceeds"));

  stage = "tagged-wan";
  await page.locator("#wan_tagged").check();
  assert.equal((await warning.textContent()).trim(), "");

  stage = "untagged-wan";
  await page.locator("#wan_tagged").uncheck();
  assert.ok((await warning.textContent()).includes(untaggedWarning));
  result = { ok: true, scenario: "one-nic-warning", browser: browser.version() };
} catch {
  result = { ok: false, scenario: "one-nic-warning", stage };
} finally {
  try {
    await browser?.close();
  } catch {
    result = { ok: false, scenario: "one-nic-warning", stage: "close" };
  }
  clearTimeout(deadline);
}

if (!timedOut) {
  process.stdout.write(`${JSON.stringify(result)}\n`);
  process.exitCode = result.ok ? 0 : 1;
}
