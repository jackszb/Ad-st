#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
update_easy_ads.py
===================

将 EasyList 的 `easylist_adservers.txt` (Adblock Plus 语法) 转换为
Shadowrocket / Surge 可直接使用的 RULE-SET 文件 `easy_ads.list`。

--------------------------------------------------------------------
设计说明 (对应任务要求，写在这里方便以后维护者查阅)
--------------------------------------------------------------------

1. 域名提取策略
   -------------
   EasyList 里绝大多数规则都是 `||domain.tld^` 或
   `||domain.tld^$option1,option2,...` 的形式。
   `||` 是"域名边界锚点"：表示匹配整个域名或其任意子域名，
   这与 Shadowrocket/Surge 的 `DOMAIN-SUFFIX` 语义完全一致，
   所以只要规则里除了 `||domain^` 和后面的 `$options`
   之外没有其它内容，就可以放心转换成 `DOMAIN-SUFFIX,domain`。

   *** 关于 $third-party ***
   `$third-party` 是这份列表里最常见的选项 (1174 行)，它表示
   "仅当该请求是第三方请求时才拦截"。DNS/域名层面的拦截天然没有
   "第三方/第一方"的概念——只要域名解析发生，就会被拦截。
   由于这些域名 100% 是广告/追踪专用域名（不会被拿来当作网站主域名），
   所以按整个域名拦截是安全、合理的近似，选项本身直接忽略，域名照常提取。
   同理，`$script`、`$document`、`$xmlhttprequest`、`$~object` 等
   资源类型选项，以及 `$popup`、`$subdocument` 等，都无法在域名层面
   区分，因此统一忽略选项、仅保留域名本身。

   *** 什么情况domain不能直接提取 ***
   如果 `||` 后面除了域名和末尾的 `^`/`$options` 之外，还带有路径、
   查询串或通配符（例如 `||bet365.com/*?affiliate=$document`、
   `||opera.com^*admaven$document`），说明规则的本意是"域名下的某个
   特定路径/参数"，而不是整个域名 —— opera.com、bet365.com 本身都是
   正常网站，直接按域名拦截会造成大量误杀。这类规则会被转成
   `URL-REGEX`（见第 3 点），而不会出现在 DOMAIN-SUFFIX 里。

   另外，如果 `||host` 后面没有 `^`、而是直接以句号结尾且并无更多字符
   （例如 `||get-me-wow.`、`||allsportsflix.$document`），说明规则作者
   故意不锁定后缀（可能未来出现在多个不同 TLD 下），这不是一个完整域名，
   同样归类到 URL-REGEX。

2. IP 规则的类型与展开策略
   -----------------------
   文件里的 IP 规则全部使用 `||` 或单个 `|` 前缀，可以归纳为两种：

   a) 完整 IPv4，以 `^` 收尾：`||167.71.252.38^`
      → 精确匹配单个地址，转换为 `IP-CIDR,167.71.252.38/32,no-resolve`

   b) "前缀式" IPv4，只写 1~3 段、以句点收尾、且没有 `^`：
      例如 `||23.109.82.`、`||142.91.159.`
      这利用了 Adblock 的默认子串匹配规则——只要 URL 里出现这个前缀
      字符串就命中，等价于把最后一段 (或几段) 通配掉，本质上就是一个
      CIDR 网段。规则要求"IP 需要展开的特殊规则要展开"，所以这里按
      "写了几段数字 × 8 = 掩码位数"通用展开：
        1 段 (`a.`)       → a.0.0.0/8
        2 段 (`a.b.`)     → a.b.0.0/16
        3 段 (`a.b.c.`)   → a.b.c.0/24
      这个规则是通用的（不依赖具体数值），以后 IP 变了也一样能正确展开。

   单独出现的 `|1.2.3.4^` (单竖线) 在语义上是"整个地址必须以此开头"，
   对纯 IP 场景效果和 `||` 相同，同样按 `/32` 处理。

   *** 无法安全转换的"类 IP"规则 ***
   文件末尾还有 9 条形如
     `/(https?:\/\/)104\.154\..{100,}/`
   的纯正则规则：它匹配"host 是 104.154.x.x 这个网段、且 URL 路径长度
   超过 100 字符"的请求，用来堵一种把广告 payload 直接放在云服务商
   IP 上、并用超长随机路径掩饰的手法。104.154.0.0/16 这种网段本身是
   Google Cloud 的公共出口 IP 段，直接展开成 IP-CIDR 拦截会连累大量
   正常流量，因此不能粗暴展开为网段，只能保留为 URL-REGEX（见下）。

3. 特殊规则 → URL-REGEX
   ---------------------
   两类情况都会转换为 Shadowrocket/Surge 支持的 `URL-REGEX`：

   a) 纯正则规则：形如 `/pattern/` 或 `/pattern/$options`，
      本身已经是正则，去掉可选的 `$options` 尾巴即可直接使用。

   b) 域名 + 路径/通配符/未闭合前缀的规则，会被正确地转换为等价正则：
        - `||`   开头 → 转成 `^https?://(?:[a-zA-Z0-9-]+\.)*`
                        （域名边界锚点：允许任意子域名前缀）
        - 域名本身      → 逐段转义 (re.escape)
        - Adblock 里的 `*`（通配符）→ 正则 `.*`
        - Adblock 里的 `^`（分隔符占位符，匹配一个非
          `[A-Za-z0-9_.%-]` 的字符）→ 正则字符类 `[^A-Za-z0-9_.%-]`
        - 其余字面字符（路径、`?`、`=`、`&`、字面 `document` 等）
          → 逐段转义后原样保留
      注意：只有当 `$` 是整条规则里**最后一个**出现的 `$` 时，才会把
      它之后的内容当作"选项"切掉；如果一行压根没有 `$`（例如
      `||gamingadlt.com^document`），那么 `^` 之后的 `document` 其实
      是路径字面量，不是选项，会被原样保留进正则 —— 这是很多简单实现
      容易出 bug 的地方（见 README 里的对比说明）。

4. 需要忽略的行
   -------------
   - 空行
   - 以 `!` 开头的注释行（含 `!!`）
   - 元素隐藏 / 样式规则：包含 `##`、`#@#`、`#$#`、`#?#` 的行
     （这些是"网页里隐藏哪个 HTML 元素"的规则，和 DNS/域名拦截无关）
   - `@@` 开头的例外(白名单)规则：这份文件目前没有任何 `@@` 行，
     但为了应对未来的更新，脚本仍然会解析 `@@||domain^` 之类的例外规则，
     并把其中的域名/IP从最终结果里排除掉，而不是简单地跳过，防止
     未来更新引入白名单时被错误拦截。
   - 无法被以上任何规则解析、又不匹配 IP/域名/正则模式的行，会被记录到
     一份"人工复核"日志里（不写进 easy_ads.list），方便以后手动检查
     EasyList 语法是否发生了变化。

输出格式
--------
单个文件 `easy_ads.list`，内容分三段：
    DOMAIN-SUFFIX,xxx
    ...
    IP-CIDR,x.x.x.x/32,no-resolve
    ...
    URL-REGEX,pattern
    ...
不包含策略字段 (REJECT 等)——按照 Shadowrocket RULE-SET 的约定，
策略在引用这个规则集的地方指定 (`RULE-SET,https://.../easy_ads.list,REJECT`)。
"""

from __future__ import annotations

import argparse
import ipaddress
import re
import sys
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_SOURCE_URL = (
    "https://raw.githubusercontent.com/easylist/easylist/master/"
    "easylist/easylist_adservers.txt"
)
OUTPUT_FILENAME = "easy_ads.list"
REVIEW_LOG_FILENAME = "easy_ads_unparsed.log"

# 一个合法的、"纯域名"应该长什么样：字母数字和连字符组成的 label，
# label 之间用点分隔，且必须至少有一个点，最后一段（TLD）必须是纯字母。
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}$"
)

_IPV4_FULL_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_IPV4_PREFIX_RE = re.compile(r"^(\d{1,3}\.){1,3}$")

# 匹配 "||host<rest>" ，host 只捕获到第一个 ^ $ / * 之前的部分
_DOUBLE_PIPE_RE = re.compile(r"^\|\|([^\^$/*]+)(.*)$")
# 单竖线：|host<rest>
_SINGLE_PIPE_RE = re.compile(r"^\|([^|][^\^$/*]*)(.*)$")
# 纯正则规则：/body/ 后面可以跟着可选的 $options（body 内部的 / 必须转义）
_PURE_REGEX_RE = re.compile(r"^/(.*)/(\$[^\s]*)?$")

_SEPARATOR_CLASS = r"[^A-Za-z0-9_.%-]"


@dataclass
class ParseResult:
    domains: set[str] = field(default_factory=set)
    ip_networks: set[str] = field(default_factory=set)  # 已经是 "x.x.x.x/nn" 字符串
    url_regexes: list[str] = field(default_factory=list)  # 保持顺序，方便排查
    exception_domains: set[str] = field(default_factory=set)
    exception_networks: set[str] = field(default_factory=set)
    unparsed: list[str] = field(default_factory=list)
    total_lines: int = 0
    ignored_lines: int = 0


def _is_cosmetic_or_comment(line: str) -> bool:
    if not line:
        return True
    if line.startswith("!"):
        return True
    # 元素隐藏/样式类规则，和域名拦截无关
    if "##" in line or "#@#" in line or "#$#" in line or "#?#" in line:
        return True
    return False


def _split_options(pattern: str) -> tuple[str, str | None]:
    """按最后一个 $ 切分 pattern 和 options。没有 $ 就说明没有 options。"""
    idx = pattern.rfind("$")
    if idx == -1:
        return pattern, None
    return pattern[:idx], pattern[idx + 1:]


def _classify_ip(host: str) -> tuple[str, str] | None:
    """host 是否是 IPv4（完整或前缀）。返回 (cidr, kind) 或 None。"""
    if _IPV4_FULL_RE.match(host):
        try:
            ipaddress.IPv4Address(host)
        except ValueError:
            return None
        return f"{host}/32", "full"
    if _IPV4_PREFIX_RE.match(host):
        groups = [g for g in host.split(".") if g != ""]
        if len(groups) > 3:
            return None
        try:
            for g in groups:
                if not (0 <= int(g) <= 255):
                    return None
        except ValueError:
            return None
        padded = groups + ["0"] * (4 - len(groups))
        mask = len(groups) * 8
        try:
            net = ipaddress.IPv4Network(f"{'.'.join(padded)}/{mask}", strict=False)
        except ValueError:
            return None
        return f"{net.network_address}/{net.prefixlen}", "prefix"
    return None


def _looks_like_plain_hostname(host: str) -> bool:
    return bool(_HOSTNAME_RE.match(host)) and not host.endswith(".")


def _build_regex_from_adblock_pattern(anchor: str, host: str, rest: str) -> str:
    """
    把 "锚点 + host + rest" 组装成一个可用的正则。
    anchor: '||' 或 '|' 或 ''
    host:   域名/前缀部分（原样字符串，尚未转义）
    rest:   host 之后剩余的字符串（已去掉 $options），可能包含 * 和 ^
    """
    pieces: list[str] = []
    if anchor == "||":
        pieces.append(r"^https?://(?:[a-zA-Z0-9-]+\.)*")
    elif anchor == "|":
        pieces.append(r"^")
    # 域名部分本身也可能包含点号等需要转义的字符
    pieces.append(re.escape(host))

    # 依次扫描 rest，把 * 和 ^ 转成对应的正则片段，其余字面转义
    i = 0
    literal_buf: list[str] = []

    def flush_literal():
        if literal_buf:
            pieces.append(re.escape("".join(literal_buf)))
            literal_buf.clear()

    while i < len(rest):
        ch = rest[i]
        if ch == "*":
            flush_literal()
            pieces.append(".*")
        elif ch == "^":
            flush_literal()
            pieces.append(_SEPARATOR_CLASS)
        else:
            literal_buf.append(ch)
        i += 1
    flush_literal()

    return "".join(pieces)


def _parse_double_or_single_pipe(line: str, result: ParseResult, *, is_exception: bool) -> bool:
    """尝试按 || 或 | 规则解析。解析成功返回 True。"""
    m = _DOUBLE_PIPE_RE.match(line)
    anchor = "||"
    if not m:
        m = _SINGLE_PIPE_RE.match(line)
        anchor = "|"
    if not m:
        return False

    host_raw, rest_raw = m.group(1), m.group(2)
    rest, _options = _split_options(rest_raw)

    # rest 为空，或者只剩下一个孤零零的 ^ ，说明是"纯域名/IP"规则
    is_pure = rest == "" or rest == "^"

    if is_pure:
        host = host_raw
        ip_hit = _classify_ip(host)
        if ip_hit is not None:
            cidr, _kind = ip_hit
            if is_exception:
                result.exception_networks.add(cidr)
            else:
                result.ip_networks.add(cidr)
            return True
        if _looks_like_plain_hostname(host) and anchor == "||":
            if is_exception:
                result.exception_domains.add(host)
            else:
                result.domains.add(host)
            return True
        # 单竖线 + 非 IP 的内容（本文件中未出现），或者看起来不像合法域名
        # （例如故意不闭合后缀的 "get-me-wow."）——都归入正则特殊规则，
        # 而不是冒险当成域名/前缀直接拦截。
        regex = _build_regex_from_adblock_pattern(anchor, host_raw, rest)
        if is_exception:
            # 例外规则里出现特殊正则的情况极为少见，这里仅记录以便人工复核
            result.unparsed.append("[exception-special] " + line)
        else:
            result.url_regexes.append(regex)
        return True

    # rest 不为空且不是单纯的 "^"：说明带路径/通配符/未识别选项，属于特殊规则
    regex = _build_regex_from_adblock_pattern(anchor, host_raw, rest)
    if is_exception:
        result.unparsed.append("[exception-special] " + line)
    else:
        result.url_regexes.append(regex)
    return True


def _parse_pure_regex(line: str, result: ParseResult, *, is_exception: bool) -> bool:
    m = _PURE_REGEX_RE.match(line)
    if not m:
        return False
    body = m.group(1)
    if is_exception:
        result.unparsed.append("[exception-regex] " + line)
    else:
        result.url_regexes.append(body)
    return True


def parse_easylist(text: str) -> ParseResult:
    result = ParseResult()
    for raw_line in text.splitlines():
        result.total_lines += 1
        line = raw_line.strip()

        if _is_cosmetic_or_comment(line):
            result.ignored_lines += 1
            continue

        is_exception = False
        working = line
        if working.startswith("@@"):
            is_exception = True
            working = working[2:]

        if not working:
            result.ignored_lines += 1
            continue

        if _parse_pure_regex(working, result, is_exception=is_exception):
            continue
        if _parse_double_or_single_pipe(working, result, is_exception=is_exception):
            continue

        # 完全没有 || / | / /regex/ 特征的裸行（EasyList 规范中極少见），
        # 记录下来人工复核，不静默丢弃。
        result.unparsed.append("[unrecognized] " + line)

    return result


def _dedupe_domains(domains: set[str]) -> set[str]:
    """
    如果 'a.b.example.com' 和 'example.com' 同时存在，DOMAIN-SUFFIX
    规则里只需要保留 'example.com' 即可（它已经覆盖所有子域名），
    去掉更长的那个可以显著缩小文件体积。
    """
    kept: set[str] = set()
    # 按标签数从少到多处理，保证短的（更泛化的）先进入 kept
    for d in sorted(domains, key=lambda s: s.count(".")):
        labels = d.split(".")
        is_covered = False
        # 检查是否已有一个更短的后缀在 kept 中
        for i in range(1, len(labels)):
            suffix = ".".join(labels[i:])
            if suffix in kept:
                is_covered = True
                break
        if not is_covered:
            kept.add(d)
    return kept


def _dedupe_networks(networks: set[str]) -> set[str]:
    """如果某个 /32 已经被同一批里更大的网段覆盖，去掉多余的 /32。"""
    nets = sorted(
        (ipaddress.ip_network(n, strict=False) for n in networks),
        key=lambda n: n.prefixlen,
    )
    kept: list[ipaddress.IPv4Network] = []
    for n in nets:
        if any(n.subnet_of(k) for k in kept):
            continue
        kept.append(n)
    return {str(n) for n in kept}


def apply_exceptions(result: ParseResult) -> None:
    if result.exception_domains:
        result.domains = {
            d for d in result.domains
            if d not in result.exception_domains
            and not any(d.endswith("." + e) for e in result.exception_domains)
        }
    if result.exception_networks:
        exc_nets = [ipaddress.ip_network(n, strict=False) for n in result.exception_networks]
        result.ip_networks = {
            n for n in result.ip_networks
            if not any(ipaddress.ip_network(n, strict=False).subnet_of(e) for e in exc_nets)
        }


def render_output(result: ParseResult, *, source_url: str, dedupe: bool) -> str:
    domains = _dedupe_domains(result.domains) if dedupe else result.domains
    networks = _dedupe_networks(result.ip_networks) if dedupe else result.ip_networks

    lines: list[str] = []
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines.append(f"# {OUTPUT_FILENAME}")
    lines.append(f"# Generated: {generated_at}")
    lines.append(f"# Source: {source_url}")
    lines.append(
        "# Auto-generated by scripts/update_easy_ads.py — 请勿手动编辑"
    )
    lines.append(
        "# $third-party / 资源类型(如 $script,$document) 等选项在域名层面"
        "无法区分，均已忽略并按整个域名拦截。"
    )
    lines.append(
        f"# 统计：DOMAIN-SUFFIX x{len(domains)}, IP-CIDR x{len(networks)}, "
        f"URL-REGEX x{len(result.url_regexes)}, 忽略 x{result.ignored_lines}, "
        f"未识别待复核 x{len(result.unparsed)}"
    )
    lines.append("")

    for d in sorted(domains):
        lines.append(f"DOMAIN-SUFFIX,{d}")
    for n in sorted(networks, key=lambda s: ipaddress.ip_network(s, strict=False)):
        lines.append(f"IP-CIDR,{n},no-resolve")
    for r in result.url_regexes:
        lines.append(f"URL-REGEX,{r}")

    return "\n".join(lines) + "\n"


def fetch_source(url: str, *, local_path: str | None = None) -> str:
    if local_path:
        return Path(local_path).read_text(encoding="utf-8", errors="replace")
    req = urllib.request.Request(url, headers={"User-Agent": "easy-ads-updater/1.0"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.read().decode("utf-8", errors="replace")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-url", default=DEFAULT_SOURCE_URL,
                         help="EasyList adservers 源文件 URL")
    parser.add_argument("--local-file", default=None,
                         help="调试用：从本地文件读取，跳过网络请求")
    parser.add_argument("--output-dir", default=".",
                         help="easy_ads.list 输出目录（默认当前目录/仓库根目录）")
    parser.add_argument("--no-dedupe", action="store_true",
                         help="关闭 DOMAIN-SUFFIX / IP-CIDR 去重（默认开启）")
    parser.add_argument("--write-review-log", action="store_true",
                         help="额外写出未识别行日志（不会提交进仓库，供 CI artifact 使用）")
    args = parser.parse_args(argv)

    try:
        text = fetch_source(args.source_url, local_path=args.local_file)
    except (urllib.error.URLError, OSError) as exc:
        print(f"[error] 下载/读取源文件失败: {exc}", file=sys.stderr)
        return 1

    result = parse_easylist(text)
    apply_exceptions(result)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    content = render_output(result, source_url=args.source_url, dedupe=not args.no_dedupe)
    out_path = output_dir / OUTPUT_FILENAME
    out_path.write_text(content, encoding="utf-8")

    print(f"[ok] 总行数={result.total_lines} 忽略={result.ignored_lines} "
          f"域名={len(result.domains)} IP段={len(result.ip_networks)} "
          f"URL-REGEX={len(result.url_regexes)} 未识别={len(result.unparsed)}")
    print(f"[ok] 已写出 {out_path}")

    if args.write_review_log and result.unparsed:
        log_path = output_dir / REVIEW_LOG_FILENAME
        log_path.write_text("\n".join(result.unparsed) + "\n", encoding="utf-8")
        print(f"[warn] 有 {len(result.unparsed)} 行未能识别，已写入 {log_path}，请人工复核")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
