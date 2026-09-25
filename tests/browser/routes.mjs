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
  if (action === "apply-draft" || action === "apply-stale-draft" || action === "apply-failed-draft") {
    await page.getByRole("button", { name: "Review pending draft", exact: true }).click();
    stage = "draft-review";
    await page.getByRole("heading", { name: "Review pending draft", exact: true }).waitFor();
    const review = await page.locator("#draft-review-summary").textContent();
    if (!review?.includes("Accepted revision") || !review?.includes(destination)) {
      throw new Error("draft review omits base revision or proposed route");
    }
    stage = "draft-apply";
    await page.getByRole("button", { name: "Apply reviewed draft", exact: true }).click();
    const expected = action === "apply-stale-draft" ? "Stale draft"
      : action === "apply-failed-draft" ? "Previous Accepted network restored" : "Accepted revision";
    await page.locator("#route-result").getByText(expected, { exact: false }).waitFor({ timeout: 60_000 });
    result = { ok: true };
  } else if (action === "reconcile-draft") {
    await page.getByRole("button", { name: "Review reconciliation", exact: true }).click();
    stage = "reconcile-review";
    await page.getByRole("heading", { name: "Review reconciliation", exact: true }).waitFor();
    const review = await page.locator("#draft-review-summary").textContent();
    if (!review?.includes("Accepted revision") ||
        !review?.includes(existingDestination) || !review?.includes(destination)) {
      throw new Error("reconciliation omits current or proposed routes or revision");
    }
    stage = "reconcile-save";
    await page.getByRole("button", { name: "Save reconciled draft", exact: true }).click();
    await page.locator("#route-result").getByText("Reconciled draft saved", { exact: false }).waitFor({ timeout: 60_000 });
    result = { ok: true };
  } else {
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
  if (action === "save") {
    await page.getByRole("button", { name: "Save draft", exact: true }).click();
    await page.locator("#route-result").getByText("Draft saved", { exact: false }).waitFor({ timeout: 60_000 });
  } else {
    await page.getByRole("button", { name: "Apply route change", exact: true }).click();
    await page.locator("#route-result").getByText(action === "reject" ? "Rejected:" : "Accepted revision", { exact: false }).waitFor({ timeout: 60_000 });
  }
  result = { ok: true };
  }
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
