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
  const interfaces = page.locator("section").filter({
    has: page.getByRole("heading", { name: "Interfaces", exact: true }),
  });
  await interfaces.getByRole("heading", { name: "Interfaces", exact: true }).waitFor();
  await page.locator("#accepted-interface-status").getByText("Accepted revision", { exact: false }).waitFor();
  await page.locator("#interface-rows [data-interface-row]").first().waitFor();

  async function rowByName(name) {
    const rows = interfaces.locator("[data-interface-row]");
    const count = await rows.count();
    for (let index = 0; index < count; index += 1) {
      const row = rows.nth(index);
      if ((await row.locator("[data-field=name]").inputValue()) === name) return row;
    }
    throw new Error(`interface ${name} is not in the editor`);
  }

  stage = "edit";
  for (const edit of input.edits || []) {
    if (edit.op === "add-vlan") {
      await interfaces.getByRole("button", { name: "Add VLAN", exact: true }).click();
      const row = interfaces.locator("[data-interface-row]").last();
      await row.locator("[data-field=name]").fill(edit.name);
      await row.locator("[data-field=role]").selectOption(edit.role);
      if (edit.parent) await row.locator("[data-field=parent]").selectOption(edit.parent);
      await row.locator("[data-field=vlan]").fill(String(edit.vlan));
      if (edit.addresses != null) await row.locator("[data-field=addresses]").fill(edit.addresses);
      await row.locator("[data-field=expose]").setChecked(!!edit.expose);
      continue;
    }
    const row = await rowByName(edit.name);
    if (edit.role) await row.locator("[data-field=role]").selectOption(edit.role);
    if (edit.parent != null) await row.locator("[data-field=parent]").selectOption(edit.parent);
    if (edit.vlan != null) await row.locator("[data-field=vlan]").fill(String(edit.vlan));
    if (edit.addresses != null) await row.locator("[data-field=addresses]").fill(edit.addresses);
    if (edit.appendAddress) {
      const current = await row.locator("[data-field=addresses]").inputValue();
      await row.locator("[data-field=addresses]").fill(`${current} ${edit.appendAddress}`.trim());
    }
    if (edit.expose != null) await row.locator("[data-field=expose]").setChecked(!!edit.expose);
    if (edit.dhcp != null) await row.locator("[data-field=dhcp]").setChecked(!!edit.dhcp);
  }

  const action = input.action;
  if (action === "save-and-apply") {
    stage = "shortcut";
    await interfaces.getByRole("button", { name: "Save and apply interfaces", exact: true }).click();
  } else if (action === "apply-draft") {
    stage = "draft-review";
    await page.getByRole("button", { name: "Review pending draft", exact: true }).click();
    await page.getByRole("heading", { name: "Review pending draft", exact: true }).waitFor();
    const review = await page.locator("#draft-review-summary").textContent();
    if (!review?.includes("Accepted revision") || (input.expectInReview && !review.includes(input.expectInReview))) {
      throw new Error("draft review omits the accepted revision or the proposed change");
    }
    stage = "draft-apply";
    await page.getByRole("button", { name: "Apply reviewed draft", exact: true }).click();
  } else {
    stage = "review";
    await interfaces.getByRole("button", { name: "Review interfaces", exact: true }).click();
    await interfaces.getByRole("heading", { name: "Review interface change", exact: true }).waitFor();
    const summary = await interfaces.locator("#interface-summary").textContent();
    if (!summary?.includes("Accepted revision") || !summary?.includes("UI exposure")) {
      throw new Error("interface review omits revision or exposure");
    }
    if (action === "save-draft") {
      stage = "save-draft";
      await interfaces.getByRole("button", { name: "Save interface draft", exact: true }).click();
    } else {
      stage = "apply";
      await interfaces.getByRole("button", { name: "Apply interface change", exact: true }).click();
    }
  }

  const expected = action === "reject" ? "Rejected:"
    : action === "save-draft" ? "networking unchanged"
      : "Accepted revision";
  stage = "result";
  await page.locator("#interface-result, #route-result").getByText(expected, { exact: false }).waitFor({ timeout: 90_000 });
  result = { ok: true };
} catch (error) {
  const message = error instanceof Error ? error.message : "interface editor failed";
  result = { ok: false, stage, error: message.slice(0, 180) };
} finally {
  if (browser) await browser.close();
  process.stdout.write(JSON.stringify(result));
  if (!result.ok) process.exitCode = 1;
}
