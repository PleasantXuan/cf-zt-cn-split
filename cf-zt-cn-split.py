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

# 1. 常用本地及私有局域网 IP 段 (保证内网打印机、NAS、路由器后台直连)
LAN_IPS = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "100.64.0.0/10",  # 运营商级 NAT (CGNAT)
    "127.0.0.0/8",  # 本地回环
    "169.254.0.0/16",  # 链路本地地址
]

# 2. 国内高频直连域名 Top 100（含 1 条 *.cn 通配规则 + 99 条核心非 .cn 域名）
TOP_CN_DOMAINS = [
    # 顶级通配（自动覆盖所有 .cn / .com.cn / .net.cn / .edu.cn）
    "*.cn",
    # 腾讯系
    "qq.com",
    "tencent.com",
    "myqcloud.com",
    "tencent-cloud.net",
    "tenpay.com",
    "weiyun.com",
    "foxmail.com",
    "dnspod.com",
    "gameloop.com",
    # 阿里系
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
    # 字节跳动
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
    # 百度系
    "baidu.com",
    "bdstatic.com",
    "baidupcs.com",
    "bcebos.com",
    "baidubce.com",
    "hao123.com",
    # 网易系
    "163.com",
    "126.net",
    "netease.com",
    "ydstatic.com",
    "163yun.com",
    "youdao.com",
    # 哔哩哔哩
    "bilibili.com",
    "bilivideo.com",
    "hdslb.com",
    "biliapi.net",
    "biligame.com",
    # 电商 / 生活 / 外卖
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
    # 视频 / 音频 / 直播
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
    # 社交 / 社区 / 资讯
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
    # 出行 / 地图
    "amap.com",
    "autonavi.com",
    "didiglobal.com",
    "didistatic.com",
    "ctrip.com",
    "qunar.com",
    # 手机生态 / 办公 / 国内 CDN
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

# 3. 国内公网 IP 数据源 (GeoIP2-CN 聚合库)
IP_URL = "https://raw.githubusercontent.com/metowolf/iplist/master/data/special/china.txt"


def get_cn_cidrs():
  """从 GeoIP2-CN 拉取聚合后的中国大陆公网 CIDR 列表"""
  r = requests.get(IP_URL, timeout=30)
  r.raise_for_status()
  cidrs = [
      line.strip()
      for line in r.text.splitlines()
      if line.strip() and not line.startswith("#")
  ]
  print(f"   国内公网 IP 数据源共获取到 {len(cidrs)} 条 CIDR")
  return cidrs


def update_split_tunnels(cn_cidrs):
  # 1. 构建内网 IP 规则 (LAN)
  lan_entries = [{"address": ip, "description": "LAN IP"} for ip in LAN_IPS]

  # 2. 构建域名规则 (自动补齐 *. 前缀以支持全子域匹配)
  formatted_domains = [
      d if d.startswith("*.") else f"*.{d}" for d in TOP_CN_DOMAINS
  ]
  domain_entries = [
      {"host": d, "description": "CN Top Domain"} for d in formatted_domains
  ]

  # 3. 计算剩余配额并分配给国内公网 IP
  reserved_count = len(lan_entries) + len(domain_entries)
  available_ip_quota = max(0, MAX_RULES - reserved_count)
  ip_entries = [
      {"address": cidr, "description": "CN IP"}
      for cidr in cn_cidrs[:available_ip_quota]
  ]

  # 4. 按优先级排序：内网 IP -> 核心域名 -> 国内公网 IP
  routes = lan_entries + domain_entries + ip_entries

  print(
      f"   内网 IP 规则：{len(lan_entries)} 条 | 域名规则："
      f" {len(domain_entries)} 条 | 公网 IP 规则：{len(ip_entries)} 条"
      f" | 合计：{len(routes)} 条"
  )

  # 5. 上限硬保底
  if len(routes) > MAX_RULES:
    print(f"⚠️ 规则总数超出 {MAX_RULES}，执行安全截断")
    routes = routes[:MAX_RULES]

  # 6. 调用 Cloudflare API 写入策略
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
  cn_cidrs = get_cn_cidrs()
  update_split_tunnels(cn_cidrs)
