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
  const ipv6 = page.locator("section").filter({
    has: page.getByRole("heading", { name: "IPv6", exact: true }),
  });
  await page.locator("#accepted-ipv6-status").getByText("Accepted revision", { exact: false }).waitFor();
  const action = input.action;
  if (action !== "observe") {
    stage = "edit";
    await ipv6.getByLabel("IPv6 on " + input.wan, { exact: true }).selectOption(input.mode);
    await ipv6.getByLabel("Request prefix delegation on " + input.wan, { exact: true }).setChecked(input.requestPd);
    if (action === "save-and-apply") {
      stage = "shortcut";
      await ipv6.getByRole("button", { name: "Save and apply IPv6", exact: true }).click();
    } else {
      stage = "review";
      await ipv6.getByRole("button", { name: "Review IPv6", exact: true }).click();
      await ipv6.getByRole("heading", { name: "Review IPv6", exact: true }).waitFor();
      const summary = await ipv6.locator("#ipv6-summary").textContent();
      if (!summary?.includes("no NAT66") || !summary?.includes("Accepted revision")) {
        throw new Error("IPv6 review omits routed forwarding or the revision");
      }
      if (action === "save-draft") {
        stage = "save-draft";
        await ipv6.getByRole("button", { name: "Save IPv6 draft", exact: true }).click();
      } else {
        stage = "apply";
        await ipv6.getByRole("button", { name: "Apply IPv6", exact: true }).click();
      }
    }
    const expected = action === "reject" ? "Rejected:"
      : action === "save-draft" ? "networking unchanged"
        : "Accepted revision";
    stage = "result";
    await page.locator("#ipv6-result").getByText(expected, { exact: false }).waitFor({ timeout: 90_000 });
  }
  stage = "live";
  let live = "";
  const deadline = Date.now() + (input.liveTimeoutMs || 5_000);
  for (;;) {
    live = (await ipv6.locator("#ipv6-live").textContent()) || "";
    if (!input.expectLive || live.includes(input.expectLive) || Date.now() > deadline) break;
    await page.waitForTimeout(1_000);
    await ipv6.getByRole("button", { name: "Refresh live IPv6", exact: true }).click();
  }
  if (input.expectLive && !live.includes(input.expectLive)) {
    throw new Error("live IPv6 never showed the expected state");
  }
  result = { ok: true, live: live.slice(0, 2000) };
} catch (error) {
  const message = error instanceof Error ? error.message : "IPv6 editor failed";
  result = { ok: false, stage, error: message.slice(0, 180) };
} finally {
  if (browser) await browser.close();
  process.stdout.write(JSON.stringify(result));
  if (!result.ok) process.exitCode = 1;
}
