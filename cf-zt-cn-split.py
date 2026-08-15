import os
import re
import requests

CF_API_TOKEN = os.getenv("CF_API_TOKEN")
ACCOUNT_ID = os.getenv("CF_ACCOUNT_ID")
PROFILE_ID = os.getenv("CF_PROFILE_ID", "")
MODE = os.getenv("MODE", "exclude")  # exclude=CN直连 | include=只有CN走WARP
ALLOWED_MODES = {"exclude", "include"}

if not all([CF_API_TOKEN, ACCOUNT_ID]):
  raise ValueError(
      "缺少环境变量！请在 GitHub Secrets 设置 CF_API_TOKEN、CF_ACCOUNT_ID"
  )

if MODE not in ALLOWED_MODES:
  raise ValueError(
      f"非法 MODE: {MODE}，只允许 {'/'.join(sorted(ALLOWED_MODES))}"
  )

HEADERS = {
    "Authorization": f"Bearer {CF_API_TOKEN}",
    "Content-Type": "application/json",
}

MAX_RULES = 4000
TARGET_DOMAIN_N = 0  # 期望域名条数，剩余配额给 IP

# Zero Trust 官方默认自带的 IPv4 / IPv6 局域网、私网保留与组播网段（共 16 条）
DEFAULT_LAN_RULES = [
    # IPv4 默认规则
    {"address": "10.0.0.0/8", "description": "-"},
    {"address": "100.64.0.0/10", "description": "-"},
    {"address": "169.254.0.0/16", "description": "DHCP Unspecified"},
    {"address": "172.16.0.0/12", "description": "-"},
    {"address": "192.0.0.0/24", "description": "-"},
    {"address": "192.168.0.0/16", "description": "-"},
    {"address": "224.0.0.0/24", "description": "-"},
    {"address": "240.0.0.0/4", "description": "-"},
    {"address": "255.255.255.255/32", "description": "DHCP Broadcast"},
    # IPv6 默认规则
    {"address": "fd00::/8", "description": "-"},
    {"address": "fe80::/10", "description": "IPv6 Link Local"},
    {"address": "ff01::/16", "description": "-"},
    {"address": "ff02::/16", "description": "-"},
    {"address": "ff03::/16", "description": "-"},
    {"address": "ff04::/16", "description": "-"},
    {"address": "ff05::/16", "description": "-"},
]

# 合法域名正则：只保留标准域名格式，过滤脏数据
VALID_DOMAIN_RE = re.compile(
    r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)

# 域名：Loyalsoldier 精选直连域名
DOMAIN_URL = "https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/direct.txt"

# IP：GeoIP2-CN
IP_URL = "https://raw.githubusercontent.com/soffchen/GeoIP2-CN/release/CN-ip-cidr.txt"


def get_cn_cidrs():
  """从GeoIP2-CN 拉取聚合的 CN CIDR 列表"""
  r = requests.get(IP_URL, timeout=30)
  r.raise_for_status()
  cidrs = [
      line.strip()
      for line in r.text.splitlines()
      if line.strip() and not line.startswith("#")
  ]
  print(f"   IP 数据源获取到 {len(cidrs)} 条 CIDR")
  return cidrs


def get_cn_domains():
  """从 Loyalsoldier/surge-rules 拉取精选 CN 直连域名列表，过滤非法格式"""
  r = requests.get(DOMAIN_URL, timeout=30)
  r.raise_for_status()
  domains = []
  for line in r.text.splitlines():
    line = line.strip()
    if not line or line.startswith("#"):
      continue
    # 兼容 DOMAIN-SUFFIX,xxx 格式
    if line.startswith("DOMAIN-SUFFIX,"):
      line = line.replace("DOMAIN-SUFFIX,", "").strip()
    # 去掉前导点（如 .baidu.com → baidu.com）
    line = line.lstrip(".")
    # 只保留合法域名格式，过滤脏数据
    if line and VALID_DOMAIN_RE.match(line):
      domains.append(f"*.{line}")
  unique = list(set(domains))
  print(f"   域名数据源获取到 {len(unique)} 条域名（已过滤非法格式）")
  return unique


def update_split_tunnels(cidrs, domains):
  # 1. 默认局域网规则
  lan_entries = DEFAULT_LAN_RULES

  # 2. 动态分配配额：先扣除局域网条数与期望域名条数，剩余配额给公网 IP
  max_domains = min(TARGET_DOMAIN_N, len(domains))
  max_ips = min(MAX_RULES - len(lan_entries) - max_domains, len(cidrs))

  # 3. 拼接规则：局域网 -> 域名 -> 国内公网 IP
  domain_entries = [
      {"host": d, "description": "CN Domain"} for d in domains[:max_domains]
  ]
  ip_entries = [
      {"address": cidr, "description": "CN IP"} for cidr in cidrs[:max_ips]
  ]
  routes = lan_entries + domain_entries + ip_entries

  print(
      f"   局域网规则：{len(lan_entries)} 条 | 域名规则："
      f" {len(domain_entries)} 条 | IP 规则：{len(ip_entries)} 条 |"
      f" 合计：{len(routes)} 条"
  )

  if len(routes) > MAX_RULES:
    print(f"⚠️  规则总数超出限制，已截断至 {MAX_RULES} 条")
    routes = routes[:MAX_RULES]

  if PROFILE_ID:
    url = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/devices/policy/{PROFILE_ID}/{MODE}"
  else:
    url = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/devices/policy/{MODE}"

  resp = requests.put(url, json=routes, headers=HEADERS)
  if resp.status_code in (200, 204):
    print(f"✅ 同步成功！{len(routes)} 条路由 | Mode: {MODE}")
  else:
    print(f"❌ 失败 {resp.status_code}: Cloudflare API 请求未成功")
    resp.raise_for_status()


if __name__ == "__main__":
  print("🔄 拉取最新 CN geo 数据...")
  cidrs = get_cn_cidrs()
  domains = get_cn_domains()
  update_split_tunnels(cidrs, domains)
