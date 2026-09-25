import { readFileSync } from "node:fs";

let browser;
let stage = "input";
let result = { ok: false, stage };
try {
  const { url, action, username, password, existingDestination, destination, gateway, device } = JSON.parse(readFileSync(0, "utf8"));
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
  stage = "edit";
  await page.getByRole("heading", { name: "Static routes", exact: true }).waitFor();
  if (action === "change" || action === "remove") {
    const row = page.locator("#route-list li").filter({ hasText: existingDestination });
    await row.getByRole("button", { name: action === "remove" ? "Remove" : "Edit", exact: true }).click();
  }
  if (action !== "remove") {
    await page.getByLabel("Destination", { exact: true }).fill(destination);
    await page.getByLabel("Next hop", { exact: true }).fill(gateway);
    await page.locator("#route-interface").selectOption(device);
    await page.getByRole("button", { name: "Review route", exact: true }).click();
  }
  stage = "review";
  await page.getByRole("heading", { name: "Review route change", exact: true }).waitFor();
  const summary = await page.locator("#route-summary").textContent();
  if (!summary?.includes(`${action === "remove" ? existingDestination : destination} via ${gateway}`)) {
    throw new Error(`incorrect route review: ${summary}`);
  }
  stage = "apply";
  await page.getByRole("button", { name: "Apply route change", exact: true }).click();
  await page.locator("#route-result").getByText(action === "reject" ? "Rejected:" : "Accepted revision", { exact: false }).waitFor({ timeout: 60_000 });
  result = { ok: true };
} catch (error) {
  result = {
    ok: false,
    stage,
    error: String(error?.message || error).slice(0, 400),
    routeResult: await browser?.contexts()?.[0]?.pages()?.[0]?.locator("#route-result")?.textContent().catch(() => ""),
  };
} finally {
  await browser?.close().catch(() => {});
}
process.stdout.write(`${JSON.stringify(result)}\n`);
process.exitCode = result.ok ? 0 : 1;
