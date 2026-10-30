// 工具函数单元测试。跑: node test/utils.test.mjs
import { b64, randB64, randHex, escapeHtml, fetchWithTimeout } from "../src/utils.js";

let pass = 0, fail = 0;
const t = (n, c) => { c ? (pass++, console.log("  ✓", n)) : (fail++, console.log("  ✗", n)); };

t("randHex 长度正确且全十六进制", () => {
  const h = randHex(16);
  return h.length === 32 && /^[0-9a-f]+$/.test(h);
});

t("randB64 输出非空且 base64 合法", () => {
  const b = randB64(24);
  return b.length > 0 && atob(b).length === 24;
});

t("b64 转换与 atob 互逆", () => {
  const data = new Uint8Array([1, 2, 3, 4, 5, 255]);
  const s = b64(data);
  const back = Uint8Array.from(atob(s), c => c.charCodeAt(0));
  return data.every((val, i) => val === back[i]);
});

t("escapeHtml 能正确转义 XSS 危险字符", () => {
  const raw = `<script>alert("xss & 'attack'")</script>`;
  const esc = escapeHtml(raw);
  return !esc.includes("<") && !esc.includes(">") &&
         esc.includes("&lt;script&gt;") &&
         esc.includes("&quot;") &&
         esc.includes("&#39;") &&
         esc.includes("&amp;");
});

t("escapeHtml 处理空/null", () => {
  return escapeHtml("") === "" && escapeHtml(null) === "" && escapeHtml(undefined) === "";
});

t("fetchWithTimeout 正常返回", async () => {
  const res = await fetchWithTimeout("https://example.com", {}, 5000);
  return res.status >= 200;
});

console.log(`\n通过 ${pass} 失败 ${fail}`);
if (fail) process.exit(1);
