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
  const policy = page.locator("section").filter({
    has: page.getByRole("heading", { name: "Firewall policy", exact: true }),
  });
  await page.locator("#accepted-policy-status").getByText("Accepted revision", { exact: false }).waitFor();
  stage = "edit";
  if (input.interface) await policy.locator("#policy-interface").selectOption(input.interface);
  if (input.source != null) await policy.locator("#policy-source").fill(input.source);
  if (input.protocol) await policy.locator("#policy-protocol").selectOption(input.protocol);
  if (input.action) await policy.locator("#policy-action").selectOption(input.action);
  const action = input.actionName || "apply";
  if (action === "save-and-apply") {
    stage = "shortcut";
    await policy.getByRole("button", { name: "Save and apply firewall policy", exact: true }).click();
  } else if (action === "apply-draft") {
    stage = "draft-review";
    await page.getByRole("button", { name: "Review pending draft", exact: true }).click();
    const review = await page.locator("#draft-review-summary").textContent();
    if (!review?.includes(input.expectInReview || "Firewall policy")) {
      throw new Error("draft review omits the firewall policy");
    }
    stage = "draft-apply";
    await page.getByRole("button", { name: "Apply reviewed draft", exact: true }).click();
  } else {
    stage = "review";
    await policy.getByRole("button", { name: "Review firewall policy", exact: true }).click();
    await policy.getByRole("heading", { name: "Review firewall policy", exact: true }).waitFor();
    const summary = await policy.locator("#policy-summary").textContent();
    if (!summary?.includes("Accepted revision") || !summary?.includes("Firewall policy")) {
      throw new Error("firewall review omits the revision");
    }
    if (action === "save-draft") {
      stage = "save-draft";
      await policy.getByRole("button", { name: "Save firewall draft", exact: true }).click();
    } else {
      stage = "apply";
      await policy.getByRole("button", { name: "Apply firewall policy", exact: true }).click();
    }
  }
  const expected = action === "reject" ? "Rejected:"
    : action === "save-draft" ? "networking unchanged"
      : "Accepted revision";
  stage = "result";
  await page.locator("#policy-result, #route-result").getByText(expected, { exact: false }).waitFor({ timeout: 90_000 });
  result = { ok: true };
} catch (error) {
  const message = error instanceof Error ? error.message : "firewall editor failed";
  result = { ok: false, stage, error: message.slice(0, 180) };
} finally {
  if (browser) await browser.close();
  process.stdout.write(JSON.stringify(result));
  if (!result.ok) process.exitCode = 1;
}
