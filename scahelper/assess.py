#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import quote

import requests
from bs4 import BeautifulSoup

SNYK_BASE = "https://security.snyk.io"
AVD_BASE = "https://avd.aliyun.com"
UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/152.0.0.0 Safari/537.36"
)
ECOSYSTEMS = (
    "maven",
    "npm",
    "pip",
    "nuget",
    "golang",
    "composer",
    "rubygems",
    "hex",
    "cocoapods",
    "cargo",
    "swift",
)
SNYK_HIGH = {"high", "critical"}
LEVEL_ORDER = {"忽略": 0, "低": 1, "中": 2, "高": 3}
VPR_ORDER = {"低": 1, "中": 2, "高": 3, "严重": 4}
SNYK_VPR = {"low": "低", "medium": "中", "high": "高", "critical": "严重"}
AVD_VPR_TEXT = {
    "严重": "严重",
    "高危": "高",
    "高": "高",
    "中危": "中",
    "中": "中",
    "低危": "低",
    "低": "低",
}

HIGH_HARM_CWE = {
    "CWE-22",
    "CWE-23",
    "CWE-36",
    "CWE-73",
    "CWE-77",
    "CWE-78",
    "CWE-89",
    "CWE-94",
    "CWE-98",
    "CWE-434",
    "CWE-502",
    "CWE-829",
    "CWE-918",
    "CWE-943",
}
HIGH_HARM_RE = re.compile(
    r"remote code execution|\brce\b|arbitrary code|code execution|"
    r"command injection|os command|execute(?:s|d)?(?: arbitrary)? code|"
    r"deserialization of untrusted data|unsafe deserialization|"
    r"path traversal|directory traversal|arbitrary file|"
    r"file (?:read|write|inclusion)|sql injection|\bsqli\b|"
    r"nosql injection|命令执行|任意代码|远程代码|反序列化|"
    r"任意文件|路径穿越|文件读取|文件写入|sql\s*注入",
    re.I,
)


@dataclass
class VersionBound:
    version: str
    inclusive: bool


@dataclass
class VersionRange:
    min: VersionBound | None = None
    max: VersionBound | None = None

    def format(self) -> str:
        if self.min and self.max:
            left = "[" if self.min.inclusive else "("
            right = "]" if self.max.inclusive else ")"
            return f"{left}{self.min.version}, {self.max.version}{right}"
        if self.max:
            op = "<=" if self.max.inclusive else "<"
            return f"{op} {self.max.version}"
        if self.min:
            op = ">=" if self.min.inclusive else ">"
            return f"{op} {self.min.version}"
        return "未知"


@dataclass
class SnykVuln:
    id: str
    title: str
    severity: str
    cvss: float | None
    cves: list[str]
    cwes: list[str]
    ranges: list[VersionRange]
    description: str
    high_harm: bool = False
    snyk_vpr: str | None = None

    def range_text(self) -> str:
        return "; ".join(r.format() for r in self.ranges) or "未知"


@dataclass
class AvdHit:
    avd_id: str
    title: str
    vpr: str | None
    score: float | None
    exploit: str
    url: str


@dataclass
class AssessedVuln:
    snyk: SnykVuln
    avd: AvdHit | None
    pair_level: str | None


@dataclass
class Result:
    package: str
    ecosystem: str
    risk: str
    risk_range: str
    reason: str
    vulns: list[AssessedVuln] = field(default_factory=list)


def detect_ecosystem(name: str) -> str:
    if name.startswith("@"):
        return "npm"
    if ":" in name:
        return "maven"
    raise SystemExit("无法判断生态，请使用 --ecosystem")


def package_artifact(name: str) -> str:
    if ":" in name:
        return name.rsplit(":", 1)[-1]
    if "/" in name:
        return name.rstrip("/").rsplit("/", 1)[-1]
    return name.lstrip("@")


def unpack_nuxt(payload: list[Any]) -> Any:
    memo: dict[int, Any] = {}

    def resolve(idx: Any) -> Any:
        if not isinstance(idx, int) or idx < 0 or idx >= len(payload):
            return idx
        if idx in memo:
            return memo[idx]
        val = payload[idx]
        if isinstance(val, list) and val and val[0] in {
            "ShallowReactive",
            "Reactive",
            "Ref",
            "ShallowRef",
        }:
            out = resolve(val[1])
            memo[idx] = out
            return out
        if isinstance(val, dict):
            out: dict[str, Any] = {}
            memo[idx] = out
            for k, v in val.items():
                out[k] = resolve(v) if isinstance(v, int) else v
            return out
        if isinstance(val, list):
            out_list: list[Any] = [None] * len(val)
            memo[idx] = out_list
            for i, v in enumerate(val):
                out_list[i] = resolve(v) if isinstance(v, int) else v
            return out_list
        memo[idx] = val
        return val

    return resolve(0)


def find_package_data(obj: Any, seen: set[int] | None = None) -> dict[str, Any] | None:
    if seen is None:
        seen = set()
    if id(obj) in seen:
        return None
    seen.add(id(obj))
    if isinstance(obj, dict):
        if "vulnerabilities" in obj and "latestReleaseVersion" in obj:
            return obj
        if "package-data" in obj:
            found = find_package_data(obj["package-data"], seen)
            if found:
                return found
        for v in obj.values():
            found = find_package_data(v, seen)
            if found:
                return found
    elif isinstance(obj, list):
        for v in obj:
            found = find_package_data(v, seen)
            if found:
                return found
    return None


def parse_bound(raw: Any) -> VersionBound | None:
    if not isinstance(raw, dict) or not raw.get("version"):
        return None
    return VersionBound(str(raw["version"]), bool(raw.get("inclusive", True)))


def parse_ranges(raw: Any) -> list[VersionRange]:
    if not isinstance(raw, list):
        return []
    out = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        out.append(VersionRange(min=parse_bound(item.get("min")), max=parse_bound(item.get("max"))))
    return out


def is_high_harm(title: str, description: str, cwes: list[str]) -> bool:
    if any(cwe.upper() in HIGH_HARM_CWE for cwe in cwes):
        return True
    return bool(HIGH_HARM_RE.search(f"{title}\n{description}"))


def parse_snyk_vulns(pkg: dict[str, Any]) -> list[SnykVuln]:
    vulns: list[SnykVuln] = []
    for item in pkg.get("vulnerabilities") or []:
        if not isinstance(item, dict):
            continue
        identifiers = item.get("identifiers") or {}
        cves = [str(x) for x in identifiers.get("CVE") or [] if x]
        cwes = [str(x) for x in identifiers.get("CWE") or [] if x]
        title = str(item.get("title") or "")
        desc = str(item.get("description") or "")
        severity = str(item.get("severity") or "").lower()
        cvss = item.get("cvssScore")
        vulns.append(
            SnykVuln(
                id=str(item.get("id") or ""),
                title=title,
                severity=severity,
                cvss=float(cvss) if isinstance(cvss, (int, float)) else None,
                cves=cves,
                cwes=cwes,
                ranges=parse_ranges(item.get("affectedVersions")),
                description=desc,
                high_harm=is_high_harm(title, desc, cwes),
                snyk_vpr=SNYK_VPR.get(severity),
            )
        )
    return vulns


def fetch_snyk(package: str, ecosystem: str) -> list[SnykVuln]:
    encoded = quote(package, safe="")
    url = f"{SNYK_BASE}/package/{ecosystem}/{encoded}"
    resp = requests.get(
        url,
        headers={"User-Agent": UA, "Accept": "text/html"},
        timeout=30,
    )
    resp.raise_for_status()
    m = re.search(r'id="__NUXT_DATA__"[^>]*>(.*?)</script>', resp.text, re.S)
    if not m:
        raise RuntimeError(f"Snyk 页面无数据: {url}")
    pkg = find_package_data(unpack_nuxt(json.loads(m.group(1))))
    if not pkg:
        raise RuntimeError(f"Snyk 未找到组件数据: {package}")
    return parse_snyk_vulns(pkg)


def find_chrome(explicit: str | None) -> str:
    if explicit:
        if not Path(explicit).exists():
            raise SystemExit(f"Chrome 不存在: {explicit}")
        return explicit
    env = os.environ.get("CHROME_PATH")
    if env and Path(env).exists():
        return env
    for name in ("chrome", "google-chrome", "chromium", "msedge"):
        found = shutil.which(name)
        if found:
            return found
    candidates = [
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/usr/bin/google-chrome",
        "/usr/bin/chromium",
    ]
    for path in candidates:
        if Path(path).exists():
            return path
    raise SystemExit("未找到 Chrome/Edge，请用 --chrome 指定")


def chrome_get(chrome: str, url: str, profile: str) -> str:
    cmd = [
        chrome,
        "--headless=new",
        "--disable-gpu",
        "--no-first-run",
        "--disable-extensions",
        "--disable-dev-shm-usage",
        f"--user-data-dir={profile}",
        "--virtual-time-budget=15000",
        "--timeout=25000",
        "--dump-dom",
        url,
    ]
    p = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=40,
        encoding="utf-8",
        errors="replace",
    )
    html = p.stdout
    idx = html.lower().find("<!doctype")
    if idx < 0:
        idx = html.lower().find("<html")
    if idx >= 0:
        html = html[idx:]
    if "_waf_" in html or "id=\"renderData\"" in html:
        raise RuntimeError(f"AVD WAF 拦截: {url}")
    return html


def parse_avd_search(html: str) -> list[dict[str, str]]:
    soup = BeautifulSoup(html, "html.parser")
    rows = []
    for tr in soup.select("table.table tbody tr"):
        tds = tr.find_all("td")
        if len(tds) < 2:
            continue
        link = tds[0].find("a")
        href = link.get("href", "") if link else ""
        avd_id = (link.get_text(strip=True) if link else tds[0].get_text(strip=True))
        m = re.search(r"AVD-\d+-\d+", avd_id) or re.search(r"id=(AVD-\d+-\d+)", href)
        if not m:
            continue
        rows.append(
            {
                "avd_id": m.group(1) if m.lastindex else m.group(0),
                "title": tds[1].get_text(" ", strip=True),
                "href": href,
            }
        )
    return rows


def pick_avd_row(rows: list[dict[str, str]], cve: str, artifact: str) -> dict[str, str] | None:
    if not rows:
        return None
    cve_u, art_u = cve.upper(), artifact.lower()
    for row in rows:
        if cve_u in row["title"].upper():
            return row
    if art_u:
        for row in rows:
            if art_u in row["title"].lower():
                return row
    return rows[0]


def parse_avd_vpr(soup: BeautifulSoup) -> tuple[str | None, float | None]:
    badge = soup.select_one("h5.header__title .badge")
    if badge:
        text = badge.get_text(strip=True)
        for key, mapped in AVD_VPR_TEXT.items():
            if key in text:
                return mapped, None
    score_el = soup.select_one(".cvss-breakdown__score")
    score = None
    if score_el:
        m = re.search(r"\d+(?:\.\d+)?", score_el.get_text())
        if m:
            score = float(m.group())
    if score is None:
        return None, None
    if score >= 9:
        return "严重", score
    if score >= 7:
        return "高", score
    if score >= 4:
        return "中", score
    return "低", score


def parse_avd_detail(html: str, avd_id: str) -> AvdHit:
    soup = BeautifulSoup(html, "html.parser")
    title_el = soup.select_one(".header__title__text")
    title = title_el.get_text(" ", strip=True) if title_el else avd_id
    vpr, score = parse_avd_vpr(soup)
    if score is None:
        score_el = soup.select_one(".cvss-breakdown__score")
        if score_el:
            m = re.search(r"\d+(?:\.\d+)?", score_el.get_text())
            if m:
                score = float(m.group())
    exploit = ""
    for metric in soup.select(".metric"):
        label = metric.select_one(".metric-label")
        value = metric.select_one(".metric-value")
        if label and value and "利用情况" in label.get_text():
            exploit = value.get_text(" ", strip=True)
            break
    return AvdHit(
        avd_id=avd_id,
        title=title,
        vpr=vpr,
        score=score,
        exploit=exploit,
        url=f"{AVD_BASE}/detail?id={avd_id}",
    )


def fetch_avd(cve: str, artifact: str, chrome: str, profile: str) -> AvdHit | None:
    search_html = chrome_get(chrome, f"{AVD_BASE}/search?q={quote(cve)}", profile)
    row = pick_avd_row(parse_avd_search(search_html), cve, artifact)
    if not row:
        return None
    detail_html = chrome_get(chrome, f"{AVD_BASE}/detail?id={row['avd_id']}", profile)
    hit = parse_avd_detail(detail_html, row["avd_id"])
    if not hit.title:
        hit.title = row["title"]
    return hit


def classify_pair(snyk_vpr: str | None, avd_vpr: str | None) -> str | None:
    vals = [v for v in (snyk_vpr, avd_vpr) if v]
    if not vals:
        return None
    if all(v == "严重" for v in vals):
        return "高"
    if any(v in {"低", "中"} for v in vals):
        return "低"
    return "中"


def version_key(version: str) -> tuple:
    parts = re.split(r"[.\-_]", version)
    key = []
    for part in parts:
        key.append((0, int(part)) if part.isdigit() else (1, part.lower()))
    return tuple(key)


def bound_less(a: VersionBound | None, b: VersionBound | None, *, is_max: bool) -> bool:
    if a is None:
        return not is_max
    if b is None:
        return is_max
    if a.version != b.version:
        return version_key(a.version) < version_key(b.version)
    if is_max:
        return (not a.inclusive) and b.inclusive
    return (not a.inclusive) and b.inclusive


def ranges_overlap_or_touch(left: VersionRange, right: VersionRange) -> bool:
    if left.max and right.min:
        if version_key(left.max.version) < version_key(right.min.version):
            return False
        if left.max.version == right.min.version and not (left.max.inclusive or right.min.inclusive):
            return False
    if right.max and left.min:
        if version_key(right.max.version) < version_key(left.min.version):
            return False
        if right.max.version == left.min.version and not (right.max.inclusive or left.min.inclusive):
            return False
    return True


def merge_ranges(ranges: list[VersionRange]) -> list[VersionRange]:
    if not ranges:
        return []
    ordered = sorted(
        ranges,
        key=lambda r: (
            version_key(r.min.version) if r.min else (),
            1 if r.min and not r.min.inclusive else 0,
        ),
    )
    merged = [VersionRange(min=ordered[0].min, max=ordered[0].max)]
    for item in ordered[1:]:
        last = merged[-1]
        if ranges_overlap_or_touch(last, item):
            if bound_less(item.min, last.min, is_max=False):
                last.min = item.min
            if bound_less(last.max, item.max, is_max=True):
                last.max = item.max
        else:
            merged.append(VersionRange(min=item.min, max=item.max))
    return merged


def format_union(ranges: list[VersionRange]) -> str:
    out = []
    for item in ranges:
        low = item.min or VersionBound("0", True)
        if item.max:
            left = "[" if low.inclusive else "("
            right = "]" if item.max.inclusive else ")"
            out.append(f"{left}{low.version}, {item.max.version}{right}")
        else:
            op = ">=" if low.inclusive else ">"
            out.append(f"{op} {low.version}")
    return " ∪ ".join(out) if out else "无"


def union_high_harm_ranges(items: list[AssessedVuln]) -> str:
    ranges = [r for x in items if x.snyk.high_harm for r in x.snyk.ranges]
    return format_union(merge_ranges(ranges))


def assess(package: str, ecosystem: str, chrome: str | None, skip_avd: bool) -> Result:
    vulns = fetch_snyk(package, ecosystem)
    snyk_high = [v for v in vulns if v.severity in SNYK_HIGH]
    if not snyk_high:
        return Result(
            package=package,
            ecosystem=ecosystem,
            risk="忽略",
            risk_range="无",
            reason="Snyk 未披露高风险或严重风险漏洞",
            vulns=[AssessedVuln(snyk=v, avd=None, pair_level=None) for v in vulns],
        )

    targets = [v for v in snyk_high if v.high_harm]
    if not targets:
        return Result(
            package=package,
            ecosystem=ecosystem,
            risk="忽略",
            risk_range="无",
            reason="Snyk 有高/严重漏洞，但均不属于可执行系统命令、操作系统文件或读取数据库的高危害类型",
            vulns=[AssessedVuln(snyk=v, avd=None, pair_level=None) for v in vulns],
        )

    artifact = package_artifact(package)
    assessed: list[AssessedVuln] = []
    profile = ""
    try:
        if not skip_avd and chrome:
            profile = tempfile.mkdtemp(prefix="sca-avd-")
        for vuln in vulns:
            avd = None
            pair = None
            if vuln in targets:
                if profile and vuln.cves:
                    try:
                        avd = fetch_avd(vuln.cves[0], artifact, chrome or "", profile)
                    except Exception as exc:
                        print(f"[warn] AVD 查询失败 {vuln.cves[0]}: {exc}", file=sys.stderr)
                pair = classify_pair(vuln.snyk_vpr, avd.vpr if avd else None)
            assessed.append(AssessedVuln(snyk=vuln, avd=avd, pair_level=pair))
    finally:
        if profile:
            shutil.rmtree(profile, ignore_errors=True)

    pairs = [x.pair_level for x in assessed if x.pair_level]
    risk = max(pairs, key=lambda x: LEVEL_ORDER[x]) if pairs else "忽略"
    top = [x for x in assessed if x.pair_level == risk]
    reasons = []
    for item in top:
        avd_vpr = item.avd.vpr if item.avd and item.avd.vpr else "无"
        cve = ",".join(item.snyk.cves) or item.snyk.id
        reasons.append(
            f"{cve}（{item.snyk.title}）Snyk VPR={item.snyk.snyk_vpr or '无'} AVD VPR={avd_vpr}"
        )
    return Result(
        package=package,
        ecosystem=ecosystem,
        risk=risk,
        risk_range=union_high_harm_ranges(assessed),
        reason="；".join(reasons) or "无可用评级",
        vulns=assessed,
    )


def print_text(result: Result) -> None:
    print(f"依赖: {result.package}")
    print(f"生态: {result.ecosystem}")
    print(f"风险程度: {result.risk}")
    print(f"风险版本: {result.risk_range}")
    print(f"原因: {result.reason}")
    print()
    print(f"{'CVE':<18} {'类型':<36} {'Snyk':<6} {'AVD':<6} {'高危害':<6} {'影响版本'}")
    for item in result.vulns:
        cve = ",".join(item.snyk.cves) or item.snyk.id
        avd = item.avd.vpr if item.avd and item.avd.vpr else "-"
        print(
            f"{cve:<18} {item.snyk.title[:36]:<36} "
            f"{(item.snyk.snyk_vpr or item.snyk.severity):<6} {avd:<6} "
            f"{'是' if item.snyk.high_harm else '否':<6} {item.snyk.range_text()}"
        )


def to_json(result: Result) -> dict[str, Any]:
    rows = []
    for item in result.vulns:
        rows.append(
            {
                "snyk_id": item.snyk.id,
                "cves": item.snyk.cves,
                "title": item.snyk.title,
                "snyk_severity": item.snyk.severity,
                "snyk_vpr": item.snyk.snyk_vpr,
                "cvss": item.snyk.cvss,
                "cwes": item.snyk.cwes,
                "high_harm": item.snyk.high_harm,
                "affected": item.snyk.range_text(),
                "avd": asdict(item.avd) if item.avd else None,
                "pair_level": item.pair_level,
            }
        )
    return {
        "package": result.package,
        "ecosystem": result.ecosystem,
        "risk": result.risk,
        "risk_range": result.risk_range,
        "reason": result.reason,
        "vulnerabilities": rows,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="评估依赖风险程度")
    parser.add_argument("package", help="依赖坐标，如 com.alibaba:fastjson")
    parser.add_argument("--ecosystem", choices=ECOSYSTEMS)
    parser.add_argument("--chrome", help="Chrome/Edge 可执行文件路径")
    parser.add_argument("--skip-avd", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    ecosystem = args.ecosystem or detect_ecosystem(args.package)
    chrome = None if args.skip_avd else find_chrome(args.chrome)
    result = assess(args.package, ecosystem, chrome, args.skip_avd)
    if args.json:
        print(json.dumps(to_json(result), ensure_ascii=False, indent=2))
    else:
        print_text(result)


if __name__ == "__main__":
    main()
