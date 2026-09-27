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
  const page = await browser.newPage({ ignoreHTTPSErrors: true, acceptDownloads: true });
  page.setDefaultTimeout(20_000);
  stage = "sign-in";
  await page.goto(input.url);
  await page.getByLabel("Username", { exact: true }).fill(input.username);
  await page.getByLabel("Password", { exact: true }).fill(input.password);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await page.getByRole("heading", { name: "Status", exact: true }).waitFor();
  const transfer = page.locator("section").filter({
    has: page.getByRole("heading", { name: "Network Desired state transfer", exact: true }),
  });
  await page.locator("#accepted-route-status").getByText("Accepted revision", { exact: false }).waitFor();
  const outcome = transfer.locator("#transfer-result");
  const action = input.action;
  if (action === "export") {
    stage = "warning";
    const warning = await transfer.locator("#transfer-warning").textContent();
    if (!warning?.includes("network secrets") || !warning.includes("no administrator accounts")) {
      throw new Error("export does not warn that the file is sensitive");
    }
    const exportButton = transfer.getByRole("button", { name: "Export network Desired state", exact: true });
    if (!(await exportButton.isDisabled())) {
      throw new Error("export is available before the sensitive-file acknowledgement");
    }
    stage = "export";
    if (input.passphrase) {
      await transfer.getByLabel("Export passphrase (optional)", { exact: true }).fill(input.passphrase);
      await transfer.getByLabel("Confirm export passphrase", { exact: true }).fill(input.passphrase);
    }
    await transfer.getByLabel("I understand this file contains network secrets", { exact: true }).check();
    const download = page.waitForEvent("download");
    await exportButton.click();
    await (await download).saveAs(input.file);
    await outcome.getByText(input.passphrase ? "encrypted with your passphrase" : "plaintext file contains network secrets", {
      exact: false,
    }).waitFor({ timeout: 60_000 });
  } else if (action === "import" || action === "reject") {
    stage = "import";
    await transfer.getByLabel("Network export file", { exact: true }).setInputFiles(input.file);
    if (input.passphrase) {
      await transfer.getByLabel("Import passphrase (encrypted files only)", { exact: true }).fill(input.passphrase);
    }
    await transfer.getByRole("button", { name: "Import into private draft", exact: true }).click();
    stage = "import-result";
    await outcome.getByText(action === "reject" ? "Import rejected:" : "networking unchanged", {
      exact: false,
    }).waitFor({ timeout: 60_000 });
    if (action === "import") {
      stage = "draft-status";
      await page.locator("#draft-status").getByText("Private pending draft", { exact: false }).waitFor();
    }
  } else if (action === "apply-draft") {
    stage = "draft-review";
    await page.getByRole("button", { name: "Review pending draft", exact: true }).click();
    const review = await page.locator("#draft-review-summary").textContent();
    if (!review?.includes("Imported network Desired state") || !review.includes("Identity configuration is unchanged")) {
      throw new Error("draft review does not identify the imported network");
    }
    if (input.secret && review.includes(input.secret)) {
      throw new Error("draft review reveals a network secret");
    }
    stage = "draft-apply";
    await page.getByRole("button", { name: "Apply reviewed draft", exact: true }).click();
    await page.locator("#route-result").getByText("Accepted revision", { exact: false }).waitFor({ timeout: 120_000 });
  } else {
    throw new Error("unknown transfer action");
  }
  stage = "redaction";
  const body = await page.locator("body").innerText();
  if (input.secret && body.includes(input.secret)) {
    throw new Error("rendered page shows a network secret");
  }
  if (input.passphrase && body.includes(input.passphrase)) {
    throw new Error("rendered page shows the export passphrase");
  }
  for (const id of ["#export-passphrase", "#export-passphrase-confirm", "#import-passphrase"]) {
    if (await page.locator(id).inputValue()) throw new Error("page keeps an export passphrase");
  }
  result = { ok: true };
} catch (error) {
  const message = error instanceof Error ? error.message : "network transfer failed";
  result = { ok: false, stage, error: message.slice(0, 180) };
} finally {
  if (browser) await browser.close();
  process.stdout.write(JSON.stringify(result));
  if (!result.ok) process.exitCode = 1;
}
