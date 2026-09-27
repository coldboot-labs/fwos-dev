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
  const shaping = page.locator("section").filter({
    has: page.getByRole("heading", { name: "Traffic shaping", exact: true }),
  });
  await page.locator("#accepted-qdisc-status").getByText("Accepted revision", { exact: false }).waitFor();
  stage = "edit";
  if (input.dev) await shaping.locator("#qdisc-dev").selectOption(input.dev);
  if (input.kind) await shaping.locator("#qdisc-kind").selectOption(input.kind);
  const action = input.action || "apply";
  if (action === "save-and-apply") {
    stage = "shortcut";
    await shaping.getByRole("button", { name: "Save and apply traffic shaping", exact: true }).click();
  } else if (action === "apply-draft") {
    stage = "draft-review";
    await page.getByRole("button", { name: "Review pending draft", exact: true }).click();
    const review = await page.locator("#draft-review-summary").textContent();
    if (!review?.includes(input.kind || "fq_codel")) {
      throw new Error("draft review omits the qdisc");
    }
    stage = "draft-apply";
    await page.getByRole("button", { name: "Apply reviewed draft", exact: true }).click();
  } else {
    stage = "review";
    await shaping.getByRole("button", { name: "Review traffic shaping", exact: true }).click();
    await shaping.getByRole("heading", { name: "Review traffic shaping", exact: true }).waitFor();
    const summary = await shaping.locator("#qdisc-summary").textContent();
    if (!summary?.includes("Accepted revision") || !summary?.includes(input.kind || "fq_codel")) {
      throw new Error("qdisc review omits the kind or revision");
    }
    if (action === "save-draft") {
      stage = "save-draft";
      await shaping.getByRole("button", { name: "Save qdisc draft", exact: true }).click();
    } else {
      stage = "apply";
      await shaping.getByRole("button", { name: "Apply traffic shaping", exact: true }).click();
    }
  }
  const expected = action === "reject" ? "Rejected:"
    : action === "save-draft" ? "networking unchanged"
      : "Accepted revision";
  stage = "result";
  await page.locator("#qdisc-result, #route-result").getByText(expected, { exact: false }).waitFor({ timeout: 90_000 });
  result = { ok: true };
} catch (error) {
  const message = error instanceof Error ? error.message : "traffic shaping editor failed";
  result = { ok: false, stage, error: message.slice(0, 180) };
} finally {
  if (browser) await browser.close();
  process.stdout.write(JSON.stringify(result));
  if (!result.ok) process.exitCode = 1;
}
