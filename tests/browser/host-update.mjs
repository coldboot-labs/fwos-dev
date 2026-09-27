import { readFileSync } from "node:fs";

let browser;
let stage = "input";
let result = { ok: false, stage };
try {
  const { url, action, username, password, image } = JSON.parse(readFileSync(0, "utf8"));
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
  await page.getByRole("heading", { name: "Host update", exact: true }).waitFor();
  const status = page.locator("#host-update-status");
  await status.getByText("Active Release:", { exact: false }).waitFor();
  const outcome = page.locator("#host-update-result");
  stage = action;
  let confirmation = "";
  if (action === "stage") {
    await page.getByLabel("Release image", { exact: true }).fill(image);
    await page.getByRole("button", { name: "Stage update", exact: true }).click();
    await outcome.getByText(/^Staging (.+ started|refused)/).waitFor({ timeout: 60_000 });
  } else if (action === "reboot") {
    page.once("dialog", async (dialog) => {
      confirmation = dialog.message();
      await dialog.accept();
    });
    await page.getByRole("button", { name: "Reboot appliance", exact: true }).click();
    await outcome.getByText(/^(Rebooting|Reboot refused)/).waitFor({ timeout: 60_000 });
  } else if (action !== "status") {
    throw new Error("unsupported Host update action");
  }
  result = {
    ok: true,
    status: await status.textContent(),
    health: await page.locator("#host-update-health").textContent(),
    operation: await page.locator("#host-update-operation").textContent(),
    result: await outcome.textContent(),
    confirmation,
    stageDisabled: await page.getByRole("button", { name: "Stage update", exact: true }).isDisabled(),
  };
} catch (error) {
  result = { ok: false, stage, error: String(error?.message || error).slice(0, 400) };
} finally {
  await browser?.close().catch(() => {});
}
process.stdout.write(`${JSON.stringify(result)}\n`);
process.exitCode = result.ok ? 0 : 1;
