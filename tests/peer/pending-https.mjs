// A bounded ordinary TLS client, controlled by the existing Rust Guest tests.
// It never accesses appliance internals or submits credentials.
import tls from "node:tls";
import { isIP } from "node:net";

const address = process.argv[2];
if (!isIP(address)) {
  process.stdout.write('{"error":"invalid peer address"}\n');
  process.exit(1);
}

let phase = "handshake";
let timer;
let received = "";
const socket = tls.connect({ host: address, port: 443, rejectUnauthorized: false });
function complete(result) {
  if (phase === "done") return;
  phase = "done";
  clearTimeout(timer);
  socket.destroy();
  process.stdin.destroy();
  process.stdout.write(`${JSON.stringify(result)}\n`, () => process.exit(result.error ? 1 : 0));
}
function deadline(milliseconds, result) {
  clearTimeout(timer);
  timer = setTimeout(() => complete(result), milliseconds);
}
deadline(10_000, { error: "TLS handshake timeout" });
socket.once("secureConnect", () => {
  phase = "waiting";
  socket.write(`GET /api/status HTTP/1.1\r\nHost: ${address}\r\n`);
  process.stdout.write('{"ready":true}\n');
  deadline(30_000, { error: "controller timeout" });
});
process.stdin.once("data", () => {
  if (phase !== "waiting") return complete({ error: "invalid controller sequence" });
  phase = "response";
  socket.write("\r\n");
  deadline(3_000, { status: null });
});
process.stdin.once("end", () => complete({ error: "controller closed" }));
socket.on("data", (chunk) => {
  if (phase !== "response") return complete({ error: "premature HTTP response" });
  received += chunk.toString("ascii");
  const end = received.indexOf("\r\n");
  if (end < 0) {
    if (received.length > 1024) complete({ error: "invalid HTTP response" });
    return;
  }
  const match = /^HTTP\/1\.[01] ([1-5][0-9]{2}) /.exec(received.slice(0, end));
  complete(match ? { status: Number(match[1]) } : { error: "invalid HTTP status" });
});
socket.on("end", () => complete(phase === "response" ? { status: null } : { error: "TLS closed before request" }));
socket.on("error", (error) => {
  complete(phase === "response" && ["ECONNRESET", "EPIPE", "ETIMEDOUT"].includes(error.code)
    ? { status: null } : { error: "TLS client failure" });
});
