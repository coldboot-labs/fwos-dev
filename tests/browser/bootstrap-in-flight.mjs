import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import tls from "node:tls";

const { port, payload, reportResponse = false } = JSON.parse(readFileSync(0, "utf8"));
assert.ok(Number.isInteger(port) && port > 0 && port < 65536);
assert.equal(typeof payload, "string");
const body = Buffer.from(payload, "utf8");
const socket = tls.connect({ host: "127.0.0.1", port, rejectUnauthorized: false });
let response = "";
socket.setTimeout(20_000, () => socket.destroy());
socket.on("error", () => {});
socket.on("data", (chunk) => { response += chunk.toString("utf8"); });
socket.on("close", () => {
  if (!reportResponse) return;
  const status = /^HTTP\/1\.1 (\d{3})/.exec(response)?.[1] ?? "0";
  const body = response.split("\r\n\r\n", 2)[1] ?? "";
  process.stdout.write(`response:${status}:${body.replaceAll("\n", " ")}\n`);
});
socket.on("secureConnect", () => {
  socket.write(
    `POST /api/bootstrap HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\n` +
      `Content-Type: application/json\r\nContent-Length: ${body.length}\r\n` +
      "Connection: close\r\n\r\n",
  );
  socket.write(body, () => process.stdout.write("sent\n"));
});
