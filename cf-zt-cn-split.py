import ipaddress
import os
import requests

CF_API_TOKEN = os.getenv("CF_API_TOKEN")
ACCOUNT_ID = os.getenv("CF_ACCOUNT_ID")
PROFILE_ID = os.getenv("CF_PROFILE_ID", "")
MODE = os.getenv("MODE", "exclude")
ALLOWED_MODES = {"exclude", "include"}

if not all([CF_API_TOKEN, ACCOUNT_ID]):
  raise ValueError(
      "缺少环境变量！请在 GitHub Secrets 设置 CF_API_TOKEN、CF_ACCOUNT_ID"
  )

HEADERS = {
    "Authorization": f"Bearer {CF_API_TOKEN}",
    "Content-Type": "application/json",
}

# 移动端友好上限（推荐 1200 ~ 1500 条，Android 秒连且覆盖 98%+ 国内流量）
MAX_RULES = 1610

# 1. 局域网 IP
LAN_IPS = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
]

# 2. 核心域名
TOP_CN_DOMAINS = [
    "*.cn",
    "qq.com",
    "tencent.com",
    "myqcloud.com",
    "tencent-cloud.net",
    "tenpay.com",
    "weiyun.com",
    "foxmail.com",
    "dnspod.com",
    "gameloop.com",
    "taobao.com",
    "alicdn.com",
    "alipay.com",
    "alipayobjects.com",
    "tmall.com",
    "alibaba.com",
    "aliyun.com",
    "aliyunpds.com",
    "alibabacloud.com",
    "aliimg.com",
    "mmstat.com",
    "tanx.com",
    "fliggy.com",
    "dingtalk.com",
    "ele.me",
    "youku.com",
    "ykimg.com",
    "1688.com",
    "cainiao.com",
    "bytedance.com",
    "douyin.com",
    "douyincdn.com",
    "byteimg.com",
    "bytegoofy.com",
    "toutiao.com",
    "toutiaocdn.com",
    "pstatp.com",
    "snssdk.com",
    "volces.com",
    "volccdn.com",
    "feishu.net",
    "ixigua.com",
    "baidu.com",
    "bdstatic.com",
    "baidupcs.com",
    "bcebos.com",
    "baidubce.com",
    "hao123.com",
    "163.com",
    "126.net",
    "netease.com",
    "ydstatic.com",
    "163yun.com",
    "youdao.com",
    "bilibili.com",
    "bilivideo.com",
    "hdslb.com",
    "biliapi.net",
    "biligame.com",
    "jd.com",
    "360buyimg.com",
    "jdcache.com",
    "pinduoduo.com",
    "yangkeduo.com",
    "meituan.com",
    "meituan.net",
    "dianping.com",
    "vip.com",
    "vipstatic.com",
    "dewu.com",
    "iqiyi.com",
    "iqiyipic.com",
    "mgtv.com",
    "hunantv.com",
    "kuaishou.com",
    "yximgs.com",
    "douyu.com",
    "huya.com",
    "ximalaya.com",
    "xmcdn.com",
    "kugou.com",
    "kuwo.com",
    "weibo.com",
    "sina.com",
    "sinaimg.com",
    "sinajs.com",
    "zhihu.com",
    "zhimg.com",
    "xiaohongshu.com",
    "xhscdn.com",
    "douban.com",
    "doubanio.com",
    "amap.com",
    "autonavi.com",
    "didiglobal.com",
    "didistatic.com",
    "ctrip.com",
    "qunar.com",
    "mi.com",
    "xiaomi.com",
    "huawei.com",
    "hicloud.com",
    "dbankcdn.com",
    "oppo.com",
    "vivo.com",
    "honor.com",
    "wps.com",
    "kingsoft.com",
    "aaplimg.com",
    "qiniu.com",
    "upyun.com",
]

IP_URL = "https://raw.githubusercontent.com/17mon/china_ip_list/master/china_ip_list.txt"


def get_cn_cidrs(max_quota):
  """拉取并利用 Python ipaddress 库进行深度超网聚合 + 大网段优先提纯"""
  r = requests.get(IP_URL, timeout=30)
  r.raise_for_status()

  raw_lines = [
      line.strip()
      for line in r.text.splitlines()
      if line.strip() and not line.startswith("#")
  ]

  # 1. 转换为 IPv4Network 对象
  networks = []
  for line in raw_lines:
    try:
      networks.append(ipaddress.ip_network(line))
    except ValueError:
      continue

  # 2. Python 原生无损超网合并 (将相邻块合成大块)
  collapsed_nets = list(ipaddress.collapse_addresses(networks))
  print(
      f"   原始条目: {len(networks)} 条 -> 无损合并后: {len(collapsed_nets)} 条"
  )

  # 3. 核心优化：按包含 IP 数量降序排列（优先保留 /8, /11, /16 等大网段）
  collapsed_nets.sort(key=lambda net: net.num_addresses, reverse=True)

  # 4. 截取前 max_quota 条最核心网段
  selected_nets = collapsed_nets[:max_quota]

  total_ips = sum(net.num_addresses for net in collapsed_nets)
  selected_ips = sum(net.num_addresses for net in selected_nets)
  coverage = (selected_ips / total_ips) * 100 if total_ips else 0

  print(
      f"   精简选入: {len(selected_nets)} 条大网段 | IP 实际覆盖率:"
      f" {coverage:.2f}%"
  )

  return [str(net) for net in selected_nets]


def update_split_tunnels():
  lan_entries = [{"address": ip, "description": "LAN IP"} for ip in LAN_IPS]
  formatted_domains = [
      d if d.startswith("*.") else f"*.{d}" for d in TOP_CN_DOMAINS
  ]
  domain_entries = [
      {"host": d, "description": "CN Top Domain"} for d in formatted_domains
  ]

  reserved_count = len(lan_entries) + len(domain_entries)
  available_ip_quota = max(0, MAX_RULES - reserved_count)

  cn_cidrs = get_cn_cidrs(available_ip_quota)
  ip_entries = [{"address": cidr, "description": "CN IP"} for cidr in cn_cidrs]

  routes = lan_entries + domain_entries + ip_entries

  print(
      f"   内网 IP: {len(lan_entries)} 条 | 域名: {len(domain_entries)} 条 | 公网"
      f" IP: {len(ip_entries)} 条 | 最终写入总数: {len(routes)} 条"
  )

  if PROFILE_ID:
    url = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/devices/policy/{PROFILE_ID}/{MODE}"
  else:
    url = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/devices/policy/{MODE}"

  resp = requests.put(url, json=routes, headers=HEADERS)
  if resp.status_code in (200, 204):
    print(f"✅ 同步成功！共写入 {len(routes)} 条路由 | Mode: {MODE}")
  else:
    print(f"❌ 失败 {resp.status_code}: {resp.text}")
    resp.raise_for_status()


if __name__ == "__main__":
  print("🔄 正在生成分流规则并同步至 Cloudflare...")
  update_split_tunnels()
