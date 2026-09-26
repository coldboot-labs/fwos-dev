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
  const services = page.locator("section").filter({
    has: page.getByRole("heading", { name: "LAN services", exact: true }),
  });
  await page.locator("#accepted-service-status").getByText("Accepted revision", { exact: false }).waitFor();
  stage = "edit";
  if (input.prefix != null) await services.getByLabel("LAN prefix", { exact: true }).fill(input.prefix);
  if (input.pool != null) await services.getByLabel("DHCP pool", { exact: true }).fill(input.pool);
  if (input.prefixDelegation != null) {
    await services.getByLabel("WAN prefix delegation", { exact: true }).fill(input.prefixDelegation);
  }
  const action = input.action;
  if (action === "save-and-apply") {
    stage = "shortcut";
    await services.getByRole("button", { name: "Save and apply LAN services", exact: true }).click();
  } else if (action === "apply-draft") {
    stage = "draft-review";
    await page.getByRole("button", { name: "Review pending draft", exact: true }).click();
    const review = await page.locator("#draft-review-summary").textContent();
    if (!review?.includes(input.expectInReview || "DHCP pool")) {
      throw new Error("draft review omits the LAN service change");
    }
    stage = "draft-apply";
    await page.getByRole("button", { name: "Apply reviewed draft", exact: true }).click();
  } else {
    stage = "review";
    await services.getByRole("button", { name: "Review LAN services", exact: true }).click();
    await services.getByRole("heading", { name: "Review LAN services", exact: true }).waitFor();
    const summary = await services.locator("#service-summary").textContent();
    if (!summary?.includes("DNS resolver") || !summary?.includes("Accepted revision")) {
      throw new Error("LAN service review omits the resolver or revision");
    }
    if (action === "save-draft") {
      stage = "save-draft";
      await services.getByRole("button", { name: "Save LAN service draft", exact: true }).click();
    } else {
      stage = "apply";
      await services.getByRole("button", { name: "Apply LAN services", exact: true }).click();
    }
  }
  const expected = action === "reject" ? "Rejected:"
    : action === "save-draft" ? "networking unchanged"
      : action === "failed" ? "Previous Accepted network restored"
        : "Accepted revision";
  stage = "result";
  await page.locator("#service-result, #route-result").getByText(expected, { exact: false }).waitFor({ timeout: 90_000 });
  result = { ok: true };
} catch (error) {
  const message = error instanceof Error ? error.message : "LAN service editor failed";
  result = { ok: false, stage, error: message.slice(0, 180) };
} finally {
  if (browser) await browser.close();
  process.stdout.write(JSON.stringify(result));
  if (!result.ok) process.exitCode = 1;
}
