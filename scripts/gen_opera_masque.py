#!/usr/bin/env python3
"""生成 Opera VPN over Cloudflare WARP(MASQUE) 的 mihomo 配置。

链路: 本机 -> MASQUE 接入点 -> Opera 落地 -> 目标

每个 Opera 落地和每个 MASQUE 接入点都组合一遍，任一环失效都有替代路径。
MASQUE 那一跳把 Opera 的地址完全藏进 QUIC 隧道，本机侧只看得到
162.159.198.x 这类 Cloudflare 地址。

用法:
    python3 gen.py <usque-config.json> <opera-proxy 路径> <输出目录>
"""
import json
import os
import re
import subprocess
import sys
from common import (
    V4, V6, PORTS, OFFICIAL_SNI, SNI_NODE,
    pem_to_b64der, masque_node, RULESETS, AI_DOMAINS
)

# Opera VPN 只有三个大区，没有国家级选项
REGIONS = {"AS": "亚洲", "EU": "欧洲", "AM": "美洲"}

def entry_name(ip, port):
    """接入点名字，短一些，后面要拼进组合节点名。"""
    if ":" in ip:
        seg = ip.split(":")[2]
        tail = ip.rsplit(":", 1)[-1]
        return f"v6-{seg}-{tail}-{port}"
    return f"{'.'.join(ip.split('.')[2:])}-{port}"


def opera_landings(binary):
    """跑 opera-proxy 拿匿名凭据和落地服务器清单。"""
    out = []
    for code, loc in REGIONS.items():
        r = subprocess.run([binary, "-country", code, "-list-proxies"],
                           capture_output=True, text=True, timeout=180)
        login = re.search(r"Proxy login: (\S+)", r.stdout)
        pw = re.search(r"Proxy password: (\S+)", r.stdout)
        if not (login and pw):
            print(f"警告: {code} 区取凭据失败，跳过", file=sys.stderr)
            continue
        seq = 0
        for line in r.stdout.splitlines():
            m = re.match(r"^([\w.-]+\.sec-tunnel\.com),([\d.]+),(\d+)$",
                         line.strip())
            if not m:
                continue
            host, ip, port = m.groups()
            seq += 1
            out.append({"loc": loc, "tag": f"{loc}{seq}", "host": host,
                        "ip": ip, "port": int(port),
                        "user": login.group(1), "pw": pw.group(1)})
    return out


def build(cfg, landings):
    priv = cfg["private_key"].strip()
    if priv.startswith("-----"):
        priv = pem_to_b64der(priv)
    pub = pem_to_b64der(cfg["endpoint_pub_key"])
    v4, v6 = cfg["ipv4"], cfg["ipv6"]

    # 1. 全部 MASQUE 接入点
    entries, proxies = [], []
    for ip in V4 + V6:
        for port in PORTS:
            n = entry_name(ip, port)
            entries.append(n)
            proxies.append(masque_node(n, ip, port, priv, pub, v4, v6))
    entries.append("官方域名")
    proxies.append(masque_node("官方域名", SNI_NODE[0], SNI_NODE[1],
                               priv, pub, v4, v6, OFFICIAL_SNI))

    # 2. 落地 × 接入点 全组合
    by_loc = {}
    for land in landings:
        for ent in entries:
            name = f"{land['tag']}@{ent}"
            by_loc.setdefault(land["loc"], []).append(name)
            proxies.append(
                f'  - {{name: "{name}", type: http, server: {land["ip"]}, '
                f'port: {land["port"]}, username: {land["user"]}, '
                f'password: {land["pw"]}, tls: true, sni: {land["host"]}, '
                f'skip-cert-verify: false, dialer-proxy: {ent}}}')

    combos = sum(len(v) for v in by_loc.values())

    def q(items, n=6):
        return "\n".join(" " * n + f'- "{x}"' for x in items)

    def plain(items, n=6):
        return "\n".join(" " * n + f"- {x}" for x in items)

    # 组合数太多，平铺在一个组里没法选，按地区收成 url-test
    loc_names = [f"{loc}线路" for loc in by_loc]
    loc_defs = "\n\n".join(f"""  - name: {loc}线路
    type: url-test
    url: https://www.gstatic.com/generate_204
    interval: 300
    tolerance: 80
    lazy: true
    proxies:
{q(tags)}""" for loc, tags in by_loc.items())

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

    yaml = f"""# Opera VPN over Cloudflare WARP (MASQUE)
# 由 GitHub Actions 自动生成，请勿手工编辑
#
# 链路: 本机 -> MASQUE 接入点 -> Opera 落地 -> 目标
# 节点名 "欧洲1@198.1-443" = 欧洲第 1 个落地，经 162.159.198.1:443 接入。
#
# 接入点 {len(entries)} 个 x 落地 {len(landings)} 个 = 组合 {combos} 个。
# 任一接入点被墙或任一落地失效，其他组合仍可用。
#
# 需要 mihomo Alpha 分支：稳定版没有 masque outbound。
# private-key 等同 WARP 账号凭据，Opera 凭据为匿名注册且会过期。

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
{plain(loc_names)}
      - 🔄 故障转移

  - name: ♻️ 自动选择
    type: url-test
    url: https://www.gstatic.com/generate_204
    interval: 300
    tolerance: 50
    lazy: true
    proxies:
{plain(loc_names)}

  - name: 🔄 故障转移
    type: fallback
    url: https://www.gstatic.com/generate_204
    interval: 180
    lazy: true
    proxies:
{plain(loc_names)}

{loc_defs}

  - name: 📹 油管视频
    type: select
    proxies:
      - 🚀 节点选择
      - ♻️ 自动选择
      - 🔄 故障转移
{plain(loc_names)}

  - name: 🎥 奈飞视频
    type: select
    proxies:
      - 🚀 节点选择
      - ♻️ 自动选择
      - 🔄 故障转移
{plain(loc_names)}

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
{plain(loc_names)}
      - 🎯 全球直连

  - name: 🤖 AI服务
    type: select
    proxies:
      - 🚀 节点选择
      - ♻️ 自动选择
      - 🔄 故障转移
{plain(loc_names)}

  - name: Ⓜ️ 微软服务
    type: select
    proxies:
      - 🎯 全球直连
      - 🚀 节点选择
      - ♻️ 自动选择
      - 🔄 故障转移
{plain(loc_names)}

  - name: 🍎 苹果服务
    type: select
    proxies:
      - 🎯 全球直连
      - 🚀 节点选择
      - ♻️ 自动选择
      - 🔄 故障转移
{plain(loc_names)}

  - name: 📢 谷歌FCM
    type: select
    proxies:
      - 🚀 节点选择
      - ♻️ 自动选择
      - 🔄 故障转移
{plain(loc_names)}
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
"""
    return yaml, len(entries), len(landings), combos


def main():
    if len(sys.argv) < 4:
        print("用法: gen.py <usque-config.json> <opera-proxy> <输出目录>",
              file=sys.stderr)
        sys.exit(1)
    cfg_path, opera_bin, outdir = sys.argv[1], sys.argv[2], sys.argv[3]

    with open(cfg_path) as f:
        cfg = json.load(f)

    landings = opera_landings(opera_bin)
    if not landings:
        sys.exit("一个 Opera 落地都没取到，可能是源 IP 被限速，换台机器再试")

    yaml, n_entry, n_land, n_combo = build(cfg, landings)

    os.makedirs(outdir, exist_ok=True)
    path = os.path.join(outdir, "opera-masque.yaml")
    with open(path, "w") as f:
        f.write(yaml)

    print(f"已生成 {path}")
    print(f"MASQUE 接入点 {n_entry} 个")
    print(f"Opera 落地   {n_land} 个: "
          + ", ".join(sorted({l['tag'] for l in landings})))
    print(f"组合节点     {n_combo} 个")


if __name__ == "__main__":
    main()
