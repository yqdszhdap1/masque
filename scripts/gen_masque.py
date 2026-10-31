#!/usr/bin/env python3
"""
注册 Cloudflare WARP (MASQUE) 设备并生成 mihomo 配置。

需要先跑 usque register 拿到 config.json，本脚本负责把它转成
带全部可用 endpoint 的 mihomo yaml。

用法:
    python3 gen_masque.py <usque-config.json> <输出目录>
"""
import json
import os
import sys
import urllib.parse
from common import (
    V4, V6, PORTS, OFFICIAL_SNI, SNI_NODE,
    pem_to_b64der, masque_node, RULESETS, AI_DOMAINS, ai_rule_lines
)

def node_name(ip, port):
    if ":" in ip:
        seg = ip.split(":")[2]
        tail = ip.rsplit(":", 1)[-1]
        return f"WARP6-{seg}-{tail}-{port}"
    return f"WARP-{'.'.join(ip.split('.')[2:])}-{port}"


def masque_links(cfg, priv, pub):
    """生成 Shadowrocket 用的 masque:// 链接。

    格式参数与字段名对齐 Shadowrocket 的 masque 实现：
    masque://<endpoint_ip>:<port>?publicKey=&privateKey=&ip=&dns=&udp=&cc=&flag=#<名称>
    publicKey 用剥掉 PEM 头尾的 base64 DER，privateKey 直接用 usque 的原值。
    逗号不转义（Shadowrocket 的 dns 字段接受逗号分隔）。
    """
    def enc(v):
        return urllib.parse.quote(str(v), safe="").replace("%2C", ",")

    lines = []
    for ip in V4 + V6:
        for port in PORTS:
            params = "&".join([
                "publicKey=" + enc(pub),
                "privateKey=" + enc(priv),
                "ip=" + enc(cfg["ipv4"]),
                "dns=" + enc("1.1.1.1, 8.8.8.8"),
                "udp=1",
                "cc=" + enc(""),
                "flag=" + enc("CDN"),
            ])
            host = "[%s]" % ip if ":" in ip else ip
            name = node_name(ip, port)
            lines.append("masque://%s:%d?%s#%s" % (host, port, params, enc(name)))
    return lines


def build(cfg):
    priv = cfg["private_key"].strip()
    if priv.startswith("-----"):
        priv = pem_to_b64der(priv)
    pub = pem_to_b64der(cfg["endpoint_pub_key"])
    v4, v6 = cfg["ipv4"], cfg["ipv6"]

    names, proxies = [], []
    for ip in V4 + V6:
        for port in PORTS:
            name = node_name(ip, port)
            names.append(name)
            proxies.append(masque_node(name, ip, port, priv, pub, v4, v6))

    names.append("WARP-官方域名")
    proxies.append(masque_node("WARP-官方域名", SNI_NODE[0], SNI_NODE[1],
                               priv, pub, v4, v6, OFFICIAL_SNI))

    ind = lambda lst, n=6: "\n".join(" " * n + f"- {x}" for x in lst)

    prov, rules = [], []
    for i, (group, url) in enumerate(RULESETS):
        pn = f"rule{i:02d}"
        prov.append(f"""  {pn}:
    type: http
    behavior: classical
    format: text
    interval: 86400
    url: {url}
    path: ./ruleset/{pn}.list""")
        rules.append(f"  - RULE-SET,{pn},{group}")

    # 内联的 AI 域名放在 RULE-SET 前面，别被上游更宽的条目抢先命中
    rules = [f"  - DOMAIN-SUFFIX,{d},🤖 AI服务" for d in AI_DOMAINS] + rules

    links = masque_links(cfg, priv, pub)

    return links, f"""# Cloudflare WARP over MASQUE - mihomo 配置
# 由 GitHub Actions 自动生成，请勿手工编辑
# 需要 mihomo Alpha 分支：稳定版没有 masque outbound
#
# 节点 {len(names)} 个，endpoint 均经真机握手实测。
# private-key 等同账号凭据。

mixed-port: 7890
allow-lan: false
mode: rule
log-level: info
ipv6: true
unified-delay: true
tcp-concurrent: true
find-process-mode: 'off'
external-controller: 127.0.0.1:9090

profile:
  store-selected: true
  store-fake-ip: true

sniffer:
  enable: true
  sniff:
    HTTP:
      ports: [80, 8080-8880]
      override-destination: true
    TLS:
      ports: [443, 8443]
    QUIC:
      ports: [443, 8443]
  skip-domain:
    - '+.push.apple.com'
    - '+.apple.com'

dns:
  enable: true
  listen: 0.0.0.0:1053
  ipv6: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter:
    - '+.lan'
    - '+.local'
    - '*.msftconnecttest.com'
    - '*.msftncsi.com'
  default-nameserver:
    - 223.5.5.5
    - 119.29.29.29
  nameserver:
    - https://223.5.5.5/dns-query
    - https://1.12.12.12/dns-query
  proxy-server-nameserver:
    - https://223.5.5.5/dns-query
  nameserver-policy:
    'geosite:cn,private':
      - https://223.5.5.5/dns-query
      - https://1.12.12.12/dns-query

proxies:
{chr(10).join(proxies)}

proxy-groups:
  - name: 🚀 节点选择
    type: select
    proxies:
      - ♻️ 自动选择
      - 🔄 故障转移
      - ☑️ 手动切换
      - DIRECT

  - name: ☑️ 手动切换
    type: select
    proxies:
{ind(names)}

  - name: ♻️ 自动选择
    type: url-test
    url: https://www.gstatic.com/generate_204
    interval: 300
    tolerance: 50
    lazy: false
    proxies:
{ind(names)}

  - name: 🔄 故障转移
    type: fallback
    url: https://www.gstatic.com/generate_204
    interval: 180
    proxies:
{ind(names)}

  - name: 📹 油管视频
    type: select
    proxies:
      - 🚀 节点选择
      - ♻️ 自动选择
      - 🔄 故障转移
      - ☑️ 手动切换
      - DIRECT

  - name: 🎥 奈飞视频
    type: select
    proxies:
      - 🚀 节点选择
      - ♻️ 自动选择
      - 🔄 故障转移
      - ☑️ 手动切换
      - DIRECT

  - name: 🌍 国外媒体
    type: select
    proxies:
      - 🚀 节点选择
      - ♻️ 自动选择
      - 🔄 故障转移
      - 🎯 全球直连

  - name: 📲 电报信息
    type: select
    proxies:
      - 🚀 节点选择
      - ♻️ 自动选择
      - 🔄 故障转移
      - ☑️ 手动切换
      - 🎯 全球直连

  - name: 🤖 AI服务
    type: select
    proxies:
      - 🚀 节点选择
      - ♻️ 自动选择
      - 🔄 故障转移
      - ☑️ 手动切换
      - DIRECT

  - name: Ⓜ️ 微软服务
    type: select
    proxies:
      - 🎯 全球直连
      - 🚀 节点选择
      - ♻️ 自动选择
      - 🔄 故障转移
      - ☑️ 手动切换

  - name: 🍎 苹果服务
    type: select
    proxies:
      - 🎯 全球直连
      - 🚀 节点选择
      - ♻️ 自动选择
      - 🔄 故障转移
      - ☑️ 手动切换

  - name: 📢 谷歌FCM
    type: select
    proxies:
      - 🚀 节点选择
      - ♻️ 自动选择
      - 🔄 故障转移
      - ☑️ 手动切换
      - 🎯 全球直连

  - name: 🎯 全球直连
    type: select
    proxies:
      - DIRECT
      - 🚀 节点选择
      - ♻️ 自动选择

  - name: 🛑 全球拦截
    type: select
    proxies:
      - REJECT
      - DIRECT

  - name: 🍃 应用净化
    type: select
    proxies:
      - REJECT
      - DIRECT

  - name: 🐟 漏网之鱼
    type: select
    proxies:
      - 🚀 节点选择
      - 🎯 全球直连
      - ♻️ 自动选择

rule-providers:
{chr(10).join(prov)}

rules:
{chr(10).join(rules)}
  - GEOIP,LAN,🎯 全球直连,no-resolve
  - GEOIP,CN,🎯 全球直连
  - MATCH,🐟 漏网之鱼
""", len(names)


def main():
    if len(sys.argv) < 3:
        print("用法: gen_masque.py <usque-config.json> <输出目录>", file=sys.stderr)
        sys.exit(1)
    src, outdir = sys.argv[1], sys.argv[2]
    with open(src) as f:
        cfg = json.load(f)

    os.makedirs(outdir, exist_ok=True)
    links, yaml, count = build(cfg)

    path = os.path.join(outdir, "warp-masque.yaml")
    with open(path, "w") as f:
        f.write(yaml)

    txt = os.path.join(outdir, "warp-masque-shadowrocket.txt")
    with open(txt, "w") as f:
        f.write("\n".join(links) + "\n")

    print(f"已生成 {path}")
    print(f"已生成 {txt}（{len(links)} 条 masque:// 链接）")
    print(f"节点数 {count}")
    print(f"内网地址 {cfg['ipv4']} / {cfg['ipv6']}")


if __name__ == "__main__":
    main()
