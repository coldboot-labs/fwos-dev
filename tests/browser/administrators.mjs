import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

delete process.env.DEBUG;
delete process.env.PWDEBUG;

let browser;
let stage = "input";
let scenario = "administrator-action";
let result;
let timedOut = false;
const deadline = setTimeout(() => {
  timedOut = true;
  process.stdout.write(`${JSON.stringify({ ok: false, scenario, stage })}\n`);
  setTimeout(() => process.exit(1), 5_000);
  Promise.resolve(browser?.close()).then(() => process.exit(1), () => process.exit(1));
}, 120_000);

try {
  const { url, action, username, password, newUsername, newPassword } = JSON.parse(readFileSync(0, "utf8"));
  assert.ok(["create", "change", "change-self", "remove"].includes(action));
  scenario = `${action}-administrator`;
  const target = new URL(url);
  assert.equal(target.protocol, "https:");
  assert.ok(["127.0.0.1", "[::1]"].includes(target.hostname));
  assert.equal(target.username, "");
  assert.equal(target.password, "");
  for (const value of [username, password, newUsername]) {
    assert.equal(typeof value, "string");
    assert.ok(value.length > 0);
  }
  assert.equal(typeof newPassword, "string");
  if (action !== "remove") assert.ok(newPassword.length > 0);

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

  stage = "sign-in";
  await page.goto(target.href);
  await page.getByLabel("Username", { exact: true }).fill(username);
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await page.getByRole("heading", { name: "Status", exact: true }).waitFor();

  stage = action;
  await page.getByRole("heading", { name: "Administrators", exact: true }).waitFor();
  if (action === "create") {
    await page.getByLabel("New administrator username", { exact: true }).fill(newUsername);
    await page.getByLabel("New administrator password", { exact: true }).fill(newPassword);
    await page.getByRole("button", { name: "Create administrator", exact: true }).click();
    await page.locator("#administrator-list").getByText(newUsername, { exact: true }).waitFor();
  } else if (action === "change" || action === "change-self") {
    stage = "change-list";
    await page.locator("#administrator-list").getByText(newUsername, { exact: true }).waitFor();
    stage = "change-select";
    await page.locator("#change-administrator-name").selectOption(newUsername);
    stage = "change-fill";
    await page.getByLabel("Replacement password", { exact: true }).fill(newPassword);
    stage = "change-click";
    await page.getByRole("button", { name: "Change password", exact: true }).click();
    stage = "change-result";
    if (action === "change-self") {
      await page.getByRole("heading", { name: "Sign in", exact: true }).waitFor();
      assert.equal(await page.getByRole("heading", { name: "Status", exact: true }).isVisible(), false);
    } else {
      await page.getByText("Password changed", { exact: true }).waitFor();
    }
  } else {
    stage = "remove-list";
    await page.locator("#administrator-list").getByText(newUsername, { exact: true }).waitFor();
    stage = "remove-select";
    await page.locator("#remove-administrator-name").selectOption(newUsername);
    stage = "remove-click";
    page.once("dialog", (dialog) => dialog.accept());
    await page.getByRole("button", { name: "Remove administrator", exact: true }).click();
    stage = "remove-result";
    await page.getByText("Administrator removed", { exact: true }).waitFor();
    await page.locator("#administrator-list").getByText(newUsername, { exact: true }).waitFor({ state: "detached" });
  }

  result = { ok: true, scenario, browser: browser.version() };
} catch {
  result = { ok: false, scenario, stage };
} finally {
  try {
    await browser?.close();
  } catch {
    result = { ok: false, scenario, stage: "close" };
  }
  clearTimeout(deadline);
}

if (!timedOut) {
  process.stdout.write(`${JSON.stringify(result)}\n`);
  process.exitCode = result.ok ? 0 : 1;
}
