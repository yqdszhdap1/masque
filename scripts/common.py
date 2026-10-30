#!/usr/bin/env python3
"""
masque 脚本公共常量与配置生成工具函数
"""
import os
import sys

# 全部经真机握手实测（2026-09-05，psg2）
# QUIC 回包不等于能建隧道：162.159.194/196/197/204 段与 v6 的 102/105 段
# 会回包但 login 失败，已剔除。
V4 = ["162.159.198.1", "162.159.198.2", "162.159.199.1", "162.159.199.2"]
V6 = ["2606:4700:103::1", "2606:4700:103::2",
      "2606:4700:104::1", "2606:4700:104::2"]
PORTS = (443, 500, 1701, 4500, 4443, 8443, 8095)

# CF 没有 A 记录指向 MASQUE 段，官方域名只能用在 SNI 上
OFFICIAL_SNI = "zt-masque.cloudflareclient.com"
SNI_NODE = ("162.159.198.1", 443)

RS = "https://raw.githubusercontent.com"
RULESETS = [
    ("🎯 全球直连", f"{RS}/cmliu/ACL4SSR/refs/heads/main/Clash/CFnat.list"),
    ("🎯 全球直连", f"{RS}/ACL4SSR/ACL4SSR/master/Clash/LocalAreaNetwork.list"),
    ("🎯 全球直连", f"{RS}/ACL4SSR/ACL4SSR/master/Clash/UnBan.list"),
    ("🛑 全球拦截", f"{RS}/ACL4SSR/ACL4SSR/master/Clash/BanAD.list"),
    ("🍃 应用净化", f"{RS}/ACL4SSR/ACL4SSR/master/Clash/BanProgramAD.list"),
    ("🍃 应用净化", f"{RS}/cmliu/ACL4SSR/main/Clash/adobe.list"),
    ("🍃 应用净化", f"{RS}/cmliu/ACL4SSR/main/Clash/IDM.list"),
    ("📢 谷歌FCM", f"{RS}/ACL4SSR/ACL4SSR/master/Clash/Ruleset/GoogleFCM.list"),
    ("🎯 全球直连", f"{RS}/ACL4SSR/ACL4SSR/master/Clash/GoogleCN.list"),
    ("🎯 全球直连", f"{RS}/ACL4SSR/ACL4SSR/master/Clash/Ruleset/SteamCN.list"),
    ("Ⓜ️ 微软服务", f"{RS}/ACL4SSR/ACL4SSR/master/Clash/Microsoft.list"),
    ("🍎 苹果服务", f"{RS}/ACL4SSR/ACL4SSR/master/Clash/Apple.list"),
    ("📲 电报信息", f"{RS}/ACL4SSR/ACL4SSR/master/Clash/Telegram.list"),
    ("🤖 AI服务", f"{RS}/ACL4SSR/ACL4SSR/master/Clash/Ruleset/OpenAi.list"),
    ("🤖 AI服务", f"{RS}/cmliu/ACL4SSR/main/Clash/Copilot.list"),
    ("🤖 AI服务", f"{RS}/cmliu/ACL4SSR/main/Clash/GithubCopilot.list"),
    ("🤖 AI服务", f"{RS}/cmliu/ACL4SSR/main/Clash/Claude.list"),
    ("🤖 AI服务", f"{RS}/cmliu/ACL4SSR/main/Clash/Gemini.list"),
    ("📹 油管视频", f"{RS}/ACL4SSR/ACL4SSR/master/Clash/Ruleset/YouTube.list"),
    ("🎥 奈飞视频", f"{RS}/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Netflix.list"),
    ("🌍 国外媒体", f"{RS}/ACL4SSR/ACL4SSR/master/Clash/ProxyMedia.list"),
    ("🌍 国外媒体", f"{RS}/cmliu/ACL4SSR/main/Clash/Emby.list"),
    ("🚀 节点选择", f"{RS}/ACL4SSR/ACL4SSR/master/Clash/ProxyLite.list"),
    ("🚀 节点选择", f"{RS}/cmliu/ACL4SSR/main/Clash/CMBlog.list"),
    ("🎯 全球直连", f"{RS}/ACL4SSR/ACL4SSR/master/Clash/ChinaDomain.list"),
    ("🎯 全球直连", f"{RS}/ACL4SSR/ACL4SSR/master/Clash/ChinaCompanyIp.list"),
]

AI_DOMAINS = [
    "openai.fm", "operator.chatgpt.com", "chat.com", "anthropic.com",
    "claude.ai", "claudeusercontent.com", "gemini.google.com", "aistudio.google.com",
    "generativelanguage.googleapis.com", "notebooklm.google.com", "notebooklm.google", "labs.google",
    "deepmind.com", "x.ai", "grok.com", "meta.ai",
    "perplexity.ai", "pplx.ai", "perplexity.com", "mistral.ai",
    "chat.mistral.ai", "cohere.com", "cohere.ai", "ai21.com",
    "together.ai", "together.xyz", "fireworks.ai", "groq.com",
    "huggingface.co", "hf.co", "huggingface.js.org", "replicate.com",
    "replicate.delivery", "runpod.io", "modal.com", "openrouter.ai",
    "poe.com", "quora.com", "cursor.com", "cursor.sh",
    "codeium.com", "windsurf.com", "tabnine.com", "sourcegraph.com",
    "phind.com", "v0.dev", "v0.app", "bolt.new",
    "lovable.dev", "devin.ai", "cognition.ai", "midjourney.com",
    "stability.ai", "stablediffusionweb.com", "leonardo.ai", "runwayml.com",
    "pika.art", "lumalabs.ai", "ideogram.ai", "recraft.ai",
    "krea.ai", "civitai.com", "elevenlabs.io", "eleven-labs.com",
    "play.ht", "suno.com", "suno.ai", "udio.com",
    "assemblyai.com", "deepgram.com", "you.com", "kagi.com",
    "exa.ai", "tavily.com", "jasper.ai", "copy.ai",
    "writesonic.com", "notion.so", "langchain.com", "langsmith.com",
    "wandb.ai", "weightsandbiases.com", "pinecone.io", "weaviate.io",
    "qdrant.tech", "chromadb.com", "deepseek.com", "moonshot.cn",
    "moonshotai.com", "kimi.com", "bigmodel.cn", "zhipuai.cn",
    "z.ai", "minimaxi.com", "minimax.io", "hailuoai.com",
    "siliconflow.cn", "dashscope.aliyuncs.com",
]

def pem_to_b64der(pem):
    return "".join(
        ln.strip() for ln in pem.strip().splitlines()
        if ln.strip() and not ln.startswith("-----")
    )

def masque_node(name, ip, port, priv, pub, v4, v6, sni=None):
    srv = f'"{ip}"' if ":" in ip else ip
    extra = f"\n    sni: {sni}" if sni else ""
    return f"""  - name: {name}
    type: masque
    server: {srv}
    port: {port}{extra}
    private-key: {priv}
    public-key: {pub}
    ip: {v4}
    ipv6: {v6}
    mtu: 1280
    udp: true
    remote-dns-resolve: true
    dns: [1.1.1.1, 2606:4700:4700::1111]"""

def build_prov_and_rules():
    prov_lines = []
    rule_lines = []
    seen = {}
    for group, url in RULESETS:
        name = url.rsplit("/", 1)[-1].replace(".list", "")
        if name in seen:
            seen[name] += 1
            pname = f"{name}-{seen[name]}"
        else:
            seen[name] = 1
            pname = name

        prov_lines.append(f"""  {pname}:
    type: http
    behavior: classical
    url: {url}
    path: ./ruleset/{pname}.yaml
    interval: 86400""")
        rule_lines.append(f"  - RULE-SET,{pname},{group}")

    ai_inlines = [f"  - DOMAIN-SUFFIX,{d},🤖 AI服务" for d in AI_DOMAINS]
    all_rules = ai_inlines + rule_lines
    return "\n".join(prov_lines), "\n".join(all_rules)
