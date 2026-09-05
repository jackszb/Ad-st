#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
build_dnsfilter.py
------------------
下载 AdGuard SDNS Filter (filter.txt)，解析其中的 AdBlock/Hosts 混合语法规则，
转换为 Shadowrocket RULE-SET 可识别的格式，输出 DNSFilter.list。

规则分类与提取策略（详见仓库 README.md 的完整说明）：

1. 注释 / 无法识别的行 —— 直接忽略：
   - 空行
   - 以 "!" 开头的 AdGuard 注释行
   - 以 "#" 开头的注释行（各子过滤器合并进来的说明文字）
   - 含有 "$badfilter" 的行（这是"取消其他规则"的元规则，不是拦截规则）
   - 无法归类到下面任何一种已知语法的行，会被记录到统计输出中以便人工复核，
     但不会写入最终文件（例如 "-1080x140-" 这类不含域名结构的横幅尺寸片段）。

2. 例外规则（以 "@@" 开头）——不会被当作拦截规则写入，
   而是记录其域名，用于从最终结果中排除同名的精确匹配拦截项。

3. 域名类规则（"||domain^"、".domain^"、"|domain^"、"://domain^" 等） ——
   提取出域名字段后，再细分：
   a. 字段本身就是合法的点分十进制 IPv4（如 ||1.2.3.4^）
      => IP-CIDR,1.2.3.4/32,no-resolve
   b. 字段形如 "A.B.C.*xxx"（前三段是合法 IPv4 段，第四段以 "*" 通配）
      （如 ||107.167.16.*.gif^，广告位经常直接用 IP+通配符请求图片）
      => 按 /24 展开：IP-CIDR,A.B.C.0/24,no-resolve
   c. 字段含有通配符 "*" 或 "?"（且不是 IP）=> DOMAIN-WILDCARD,字段
   d. 其他普通域名 => DOMAIN-SUFFIX,字段
      （AdGuard 的 "||" 语义本身就是"该域名及其所有子域名"，
      与 Shadowrocket 的 DOMAIN-SUFFIX 语义等价）

4. 正则规则（形如 "/^1\\.2\\.3\\.(4|5)/"）——
   先判断是否为"纯 IP 正则"（字符集里只允许数字/圆括号/方括号/花括号/竖线/冒号/$/^/d/.等），
   若是，则逐段展开每个 IPv4 段可能取值（用穷举 0-255 试匹配的方式，
   不依赖手写正则语义解析，稳妥可靠），再用 ipaddress.summarize_address_range
   合并成最小 CIDR 集合写出多条 IP-CIDR；这样即使源文件里出现的具体 IP 变化，
   只要正则的"段结构"不变，脚本依然可以正确展开。
   若不是纯 IP 正则（例如包含协议前缀、超长通配 ".{100,}"、或用于匹配一段
   随机域名的正则），则退化为 Shadowrocket 支持的 URL-REGEX 规则原样保留，
   保证规则语义不丢失。

5. 输出文件按类型分组：DOMAIN-SUFFIX / DOMAIN-WILDCARD 在前，URL-REGEX 其次，
   IP-CIDR 放最后，与 shadowrocket 规则集示例文件的顺序风格一致。
"""

from __future__ import annotations

import ipaddress
import re
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path

SOURCE_URL = "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt"
OUTPUT_FILE = "DNSFilter.list"

# ---------------------------------------------------------------------------
# 基础工具函数
# ---------------------------------------------------------------------------

_IPV4_RE = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")
_IPV4_WILDCARD_RE = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.\*")
_FIELD_RE = re.compile(r"^([^\^$]+)")

# 明显不是域名后缀（而是文件扩展名/资源类型）的"伪TLD"，出现在裸片段规则末尾时
# 说明该片段本身就不是一个域名，应当忽略而不是误当成 DOMAIN-SUFFIX
_FAKE_TLD_BLOCKLIST = {
    "gif", "jpg", "jpeg", "png", "js", "css", "swf", "php",
    "html", "htm", "json", "xml", "webp", "ico",
}
# 一个"看起来像域名"的最基本形状：至少两段，每段由字母数字/连字符/通配符组成，
# 且最后一段（类TLD）至少2个字母（允许通配符）
_DOMAIN_SHAPE_RE = re.compile(
    r"^[A-Za-z0-9*?][A-Za-z0-9*?\-]*(\.[A-Za-z0-9*?][A-Za-z0-9*?\-]*)+$"
)


def looks_like_domain(field: str) -> bool:
    if not field or "." not in field:
        return False
    if not _DOMAIN_SHAPE_RE.match(field):
        return False
    last_label = field.rsplit(".", 1)[-1].lower()
    if last_label in _FAKE_TLD_BLOCKLIST:
        return False
    return True


def is_valid_ipv4(s: str) -> bool:
    m = _IPV4_RE.match(s)
    if not m:
        return False
    return all(0 <= int(g) <= 255 for g in m.groups())


def is_valid_ipv6(s: str) -> bool:
    try:
        ipaddress.IPv6Address(s)
        return True
    except ValueError:
        return False


def extract_field(body: str) -> str:
    """从形如 'example.com^$third-party' 的字符串中截取到 '^' 或 '$' 之前的内容。"""
    m = _FIELD_RE.match(body)
    return m.group(1) if m else ""


def classify_domain_field(field: str):
    """把一个已经剥离了 ||/|/./:// 前缀 及 ^/$ 后缀的“域名字段”分类为
    具体的 shadowrocket 规则 (TYPE, VALUE) 列表。"""
    d = field.strip().rstrip(".")
    if not d:
        return []

    # (b) 通配 IP：107.167.16.*.gif -> 107.167.16.0/24
    m = _IPV4_WILDCARD_RE.match(d)
    if m:
        o1, o2, o3 = m.groups()
        if all(0 <= int(x) <= 255 for x in (o1, o2, o3)):
            return [("IP-CIDR", f"{o1}.{o2}.{o3}.0/24,no-resolve")]

    # (a) 纯 IPv4 字面量
    if is_valid_ipv4(d):
        return [("IP-CIDR", f"{d}/32,no-resolve")]

    # 纯 IPv6 字面量（filter.txt 目前未出现，但未来若源数据加入 IPv6 广告服务器，
    # 这里可以正确识别为 /128，而不会被误当成域名字符串写出一个不合法的行）
    if ":" in d and is_valid_ipv6(d):
        return [("IP-CIDR", f"{d}/128,no-resolve")]

    # (c) 域名通配符
    if "*" in d or "?" in d:
        return [("DOMAIN-WILDCARD", d)]

    # (d) 普通域名
    return [("DOMAIN-SUFFIX", d)]


def summarize_ints(int_values):
    """把一组整数(0-255^4范围内的IP整数表示)按连续区间合并为最小CIDR集合。"""
    vals = sorted(set(int_values))
    nets = []
    if not vals:
        return nets
    start = prev = vals[0]
    for v in vals[1:]:
        if v == prev + 1:
            prev = v
            continue
        nets.extend(
            ipaddress.summarize_address_range(
                ipaddress.IPv4Address(start), ipaddress.IPv4Address(prev)
            )
        )
        start = prev = v
    nets.extend(
        ipaddress.summarize_address_range(
            ipaddress.IPv4Address(start), ipaddress.IPv4Address(prev)
        )
    )
    return nets


_PURE_IP_REGEX_CHARSET = set("0123456789().[]{}|,-:$d.\\")


def expand_ip_regex(core: str):
    """尝试把一个“看起来像纯IPv4"的正则片段展开为具体的 IP-CIDR 列表。
    core: 已去掉最外层 // 、已去掉开头 ^ 、"\\." 已归一化为 "." 的正则内容。
    返回 CIDR 字符串列表；无法展开时返回 None。"""
    if not core or any(c not in _PURE_IP_REGEX_CHARSET for c in core):
        return None

    parts = core.split(".", 3)
    if len(parts) != 4:
        return None

    p1, p2, p3, p4 = parts
    # 第4段之后可能还跟着端口相关的内容，如 ":" 或 ":(80|443)$"，与IP取值无关，去掉
    p4 = p4.split(":")[0].rstrip("$")

    octet_patterns = [p1, p2, p3, p4]
    octet_value_sets = []
    for pat in octet_patterns:
        if not pat:
            return None
        try:
            rx = re.compile(pat)
        except re.error:
            return None
        vals = [i for i in range(256) if rx.fullmatch(str(i))]
        if not vals:
            return None
        octet_value_sets.append(vals)

    # 组合数超过安全阈值就放弃展开（避免异常正则导致规则集爆炸）
    total = 1
    for s in octet_value_sets:
        total *= len(s)
    if total > 4096:
        return None

    ip_ints = []
    for a in octet_value_sets[0]:
        for b in octet_value_sets[1]:
            for c in octet_value_sets[2]:
                for d in octet_value_sets[3]:
                    ip_ints.append((a << 24) | (b << 16) | (c << 8) | d)

    nets = summarize_ints(ip_ints)
    return [f"{n},no-resolve" for n in (str(net) for net in nets)]


def handle_regex_rule(raw_line: str):
    """处理形如 /pattern/ 的正则规则，返回 (TYPE, VALUE) 列表。"""
    pattern = raw_line.strip()
    if pattern.startswith("/"):
        pattern = pattern[1:]
    if pattern.endswith("/"):
        pattern = pattern[:-1]

    normalized = pattern.replace("\\.", ".")
    core = normalized[1:] if normalized.startswith("^") else normalized

    cidrs = expand_ip_regex(core)
    if cidrs:
        return [("IP-CIDR", c) for c in cidrs]

    # 回退方案：保留为 URL-REGEX，尽量补全协议前缀以提升匹配准确性
    p = pattern
    if p.startswith("^") and "http" not in p:
        p = "^https?:\\/\\/" + p[1:]
    return [("URL-REGEX", p)]


# ---------------------------------------------------------------------------
# 主解析流程
# ---------------------------------------------------------------------------


def parse_filter(text: str):
    rules = []          # 有序去重后的 (TYPE, VALUE)
    seen = set()
    excluded_exact = set()   # 来自 @@ 例外规则的精确域名
    unmatched = []      # 无法识别、被忽略的原始行（用于日志/复核）
    stats = {
        "total_lines": 0,
        "comment_or_empty": 0,
        "badfilter": 0,
        "exception": 0,
        "regex": 0,
        "domain_rule": 0,
        "unmatched": 0,
    }

    def add(t, v):
        key = (t, v)
        if key not in seen:
            seen.add(key)
            rules.append(key)

    for raw in text.splitlines():
        stats["total_lines"] += 1
        s = raw.strip()

        if not s or s.startswith("!") or s.startswith("#"):
            stats["comment_or_empty"] += 1
            continue

        if "$badfilter" in s:
            stats["badfilter"] += 1
            continue

        # 例外规则
        if s.startswith("@@"):
            stats["exception"] += 1
            body = s[2:]
            if body.startswith("||"):
                field = extract_field(body[2:]).rstrip(".")
                if field:
                    excluded_exact.add(field)
            # @@/regex/ 形式的例外无法安全地"取消"某条已展开规则，直接忽略
            continue

        # 正则规则： /.../
        if s.startswith("/") and len(s) > 1 and s.rstrip().endswith("/"):
            stats["regex"] += 1
            for t, v in handle_regex_rule(s):
                add(t, v)
            continue

        field = None
        if s.startswith("||"):
            field = extract_field(s[2:])
        elif s.startswith("://"):
            field = extract_field(s[3:])
        elif s.startswith("."):
            field = extract_field(s[1:])
        elif s.startswith("|") and not s.startswith("||"):
            body = s[1:].rstrip("|")
            field = extract_field(body)

        if field is not None:
            field = field.rstrip(".")
            if field:
                stats["domain_rule"] += 1
                for t, v in classify_domain_field(field):
                    add(t, v)
                continue

        # 兜底：既没有 ||/|/./:// 前缀，也不是正则/例外/badfilter 的"裸"片段。
        # 这类行常见于两种情况：
        #  (1) 作者偷懒直接写了裸域名 + "^"，如 "prd.api.bleacherreport.com^"
        #  (2) 用一个字面量前缀（最常见是 "-"）拼接域名，
        #      如 "-s2s.sensic.net^"、"-adx-*.rayjump.com^"
        # 对这两种情况，只要剥离前后缀后"形似域名"，就按域名规则处理；
        # 否则（如 "-1080x140-"、"-ad123-" 这类纯广告位尺寸/关键词片段，
        # 根本不含域名结构）按需求4的授权，脚本将其界定为忽略行。
        bare = extract_field(s)
        candidate = bare
        if candidate.startswith("-") and not candidate.startswith("--"):
            candidate = candidate[1:]
        candidate = candidate.rstrip(".")

        if looks_like_domain(candidate):
            stats["domain_rule"] += 1
            for t, v in classify_domain_field(candidate):
                add(t, v)
            continue

        stats["unmatched"] += 1
        unmatched.append(s)

    # 应用例外：精确匹配域名的拦截规则予以剔除
    final = [
        (t, v)
        for (t, v) in rules
        if not ((t in ("DOMAIN-SUFFIX", "DOMAIN-WILDCARD")) and v in excluded_exact)
    ]

    return final, unmatched, stats


# ---------------------------------------------------------------------------
# 输出
# ---------------------------------------------------------------------------

_TYPE_ORDER = {"DOMAIN-SUFFIX": 0, "DOMAIN-WILDCARD": 1, "URL-REGEX": 2, "IP-CIDR": 3}


def render_output(rules, source_url: str) -> str:
    rules_sorted = sorted(rules, key=lambda r: (_TYPE_ORDER.get(r[0], 9), r[1]))
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = [
        "# DNSFilter.list",
        f"# Generated: {now}",
        f"# Source: {source_url}",
        f"# Total rules: {len(rules_sorted)}",
        "# Auto-generated by scripts/build_dnsfilter.py — 请勿手动编辑",
        "",
    ]
    for t, v in rules_sorted:
        lines.append(f"{t},{v}")
    lines.append("")
    return "\n".join(lines)


def fetch_source(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "dnsfilter-builder/1.0"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.read().decode("utf-8", errors="replace")


def main():
    local_override = None
    if len(sys.argv) > 1:
        local_override = sys.argv[1]

    try:
        if local_override:
            text = Path(local_override).read_text(encoding="utf-8")
        else:
            text = fetch_source(SOURCE_URL)
    except (urllib.error.URLError, OSError) as e:
        print(f"[ERROR] 下载源文件失败: {e}", file=sys.stderr)
        sys.exit(1)

    rules, unmatched, stats = parse_filter(text)
    output = render_output(rules, SOURCE_URL)

    Path(OUTPUT_FILE).write_text(output, encoding="utf-8")

    print("==== build_dnsfilter 统计 ====")
    for k, v in stats.items():
        print(f"  {k}: {v}")
    print(f"  输出规则总数: {len(rules)}")
    print(f"  未能识别(忽略)行数: {len(unmatched)}")
    if unmatched:
        sample = unmatched[:20]
        print("  未识别行样例(最多20条):")
        for s in sample:
            print(f"    {s}")


if __name__ == "__main__":
    main()
