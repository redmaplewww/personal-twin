#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""twin —— 个人数字孪生 CLI（D:\\personal-twin 唯一入口）

命令：
  twin check                          自检：仓库结构 + kdbx 可解锁 + git 状态
  twin unlock [--ttl 900]             解锁会话（交互输主密码，写临时会话文件，默认15分钟）
  twin lock                           立即清除会话
  twin list [--group X]               列凭据条目（无密值）
  twin get <条目> [--field password|username|url|notes]   取单个字段（默认 password）
  twin add <条目> [--username U] [--url U] [--notes N] [--group G] [--force]   新增/覆盖凭据
  twin rm <条目>                       删除条目（永久，需确认）
  twin backup [--ssh]                 加密备份 contacts → 同步盘加密区 + kdbx 副本 + git 快照
  twin audit [--path 额外目录]         扫描同步盘/知识库/备份区的 L1 泄露（报告只引用令牌号）
  twin restore <备份目录> [--dest D] [--force]   新机恢复向导

主密码来源优先级：会话文件 > 环境变量 TWIN_PW > stdin（非tty）> getpass 交互。
安全约定：输出永远只有请求的单个字段；审计日志只记条目名不记值。
"""
import argparse
import getpass
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

ROOT = os.environ.get("TWIN_HOME", r"D:\personal-twin")
BACKUP_DEST = os.environ.get("TWIN_BACKUP_DEST", ROOT + "-backup")  # 加密备份目的地（默认与仓库同级）
VAULT = os.environ.get("TWIN_VAULT", "")  # 可选：额外参与泄露审计的目录（如知识库）
KDBX = os.path.join(ROOT, "secrets.kdbx")
PWFILE = os.path.join(ROOT, "MASTER-PASSWORD.txt")
SESSION = os.path.join(tempfile.gettempdir(), "twin-session")
AUDIT_LOG = os.path.join(ROOT, "audit.log")
TOKENS = os.path.join(ROOT, "inventory", "audit-tokens.txt")
AUTOUNLOCK = os.path.join(ROOT, ".autounlock")  # DPAPI(用户+本机绑定)保护的主密码，开启后免人工输入


# ---------- DPAPI（Windows 用户级加密，无第三方依赖） ----------

def _dpapi(data: bytes, protect: bool) -> bytes:
    import ctypes
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    buf = ctypes.create_string_buffer(data)
    blob_in = DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    blob_out = DATA_BLOB()
    fn = ctypes.windll.crypt32.CryptProtectData if protect else ctypes.windll.crypt32.CryptUnprotectData
    ok = fn(ctypes.byref(blob_in), "twin" if protect else None, None, None, None, 0, ctypes.byref(blob_out))
    if not ok:
        raise OSError("DPAPI failed (protect=%s)" % protect)
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)


def autounlock_pw():
    """返回 DPAPI 自动解锁的主密码；未启用/解密失败返回 None。"""
    try:
        blob = io.open(AUTOUNLOCK, "rb").read()
        import base64
        return _dpapi(base64.b64decode(blob), protect=False).decode("utf-8")
    except Exception:
        return None
AUDIT_LOG = os.path.join(ROOT, "audit.log")
TOKENS = os.path.join(ROOT, "inventory", "audit-tokens.txt")
AUDIT_ROOTS = [
    ("知识库", VAULT),
    ("备份区", BACKUP_DEST),
]
TEXT_EXT = {".md", ".txt", ".json", ".csv", ".yaml", ".yml", ".html", ".htm", ".py", ".toml"}
MAX_FILE = 5 << 20
ALLOWLIST = os.path.join(ROOT, "inventory", "audit-allowlist.txt")


def _load_allowlist():
    """按行读路径（绝对或相对知识库根），# 开头为注释。命中者只报 INFO 不算失败。"""
    out = set()
    if os.path.exists(ALLOWLIST):
        for line in io.open(ALLOWLIST, encoding="utf-8"):
            line = line.strip()
            if line and not line.startswith("#"):
                out.add(os.path.normcase(line))
                out.add(os.path.normcase(os.path.join(VAULT, line)))
    return out


def log(msg):
    print(msg, flush=True)


def audit_record(action):
    with io.open(AUDIT_LOG, "a", encoding="utf-8") as f:
        f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')}\t{action}\n")


# ---------- 密码获取 ----------

def _try_session():
    try:
        d = json.load(io.open(SESSION, encoding="utf-8"))
        if d.get("exp", 0) > time.time():
            return d["pw"]
        os.remove(SESSION)
    except Exception:
        pass
    return None


def cmd_autounlock(args):
    if args.op == "status":
        on = autounlock_pw() is not None
        log("autounlock: " + (f"已开启（DPAPI，绑定本机用户 {os.environ.get('USERNAME','?')}；twin autounlock off 关闭）" if on else "未开启（取值需 unlock/主密码）"))
        return
    if args.op == "on":
        pw = get_master_pw(allow_session=False, pw_stdin=PW_STDIN)
        if not pw:
            log("需要主密码以生成自动解锁块")
            sys.exit(2)
        from pykeepass import PyKeePass
        try:
            PyKeePass(KDBX, password=pw)
        except Exception:
            log("主密码错误")
            sys.exit(3)
        import base64
        io.open(AUTOUNLOCK, "wb").write(base64.b64encode(_dpapi(pw.encode("utf-8"), protect=True)))
        try:
            os.chmod(AUTOUNLOCK, 0o600)
        except OSError:
            pass
        audit_record("autounlock-on")
        log(f"已开启：{AUTOUNLOCK}（DPAPI 绑定当前 Windows 用户与本机；换机/换用户无效，恢复时仍需人工输入主密码）")
    elif args.op == "off":
        if os.path.exists(AUTOUNLOCK):
            os.remove(AUTOUNLOCK)
        audit_record("autounlock-off")
        log("已关闭：回到 unlock/主密码模式")


def get_master_pw(allow_session=True, pw_stdin=False):
    if allow_session:
        pw = _try_session()
        if pw:
            return pw
        pw = autounlock_pw()  # DPAPI 自动解锁：无感取值（边界=本机用户会话）
        if pw:
            return pw
    pw = os.environ.get("TWIN_PW")
    if pw:
        return pw
    if pw_stdin:
        line = sys.stdin.readline()
        return line.strip() if line else None
    try:
        if sys.stdin.isatty() and sys.stderr.isatty():
            return getpass.getpass("主密码: ")
    except Exception:
        pass
    line = sys.stdin.readline()
    return line.strip() if line else None


PW_STDIN = False


def open_kdbx(allow_session=True):
    from pykeepass import PyKeePass
    pw = get_master_pw(allow_session, pw_stdin=PW_STDIN)
    if not pw:
        log("未提供主密码。请先 `twin unlock`，或 stdin 传入，或设 TWIN_PW（不推荐）。")
        sys.exit(2)
    try:
        return PyKeePass(KDBX, password=pw)
    except Exception:
        log("主密码错误或 kdbx 损坏。")
        sys.exit(3)


# ---------- 命令实现 ----------

def cmd_check(args):
    problems = []
    for rel in ["profile.md", "contacts.md", "accounts.md", "README.md", "inventory", "scripts"]:
        if not os.path.exists(os.path.join(ROOT, rel)):
            problems.append(f"缺文件/目录: {rel}")
    if not os.path.exists(KDBX):
        problems.append("缺 secrets.kdbx")
    if os.path.exists(PWFILE):
        problems.append("MASTER-PASSWORD.txt 仍在（验证后应删除；autounlock 开启后它已无必要）")
    if os.path.exists(AUTOUNLOCK):
        log("[autounlock] 已开启（DPAPI 免密模式）")
    kp = open_kdbx()
    log(f"[kdbx] 解锁成功，{len(kp.entries)} 条，分组: " + ", ".join(g.name for g in kp.root_group.subgroups))
    r = subprocess.run(["git", "-C", ROOT, "status", "--short"], capture_output=True, text=True)
    if r.stdout.strip():
        problems.append(f"git 有未提交变更:\n{r.stdout.strip()[:400]}")
    enc = os.path.join(BACKUP_DEST, "contacts.md.enc")
    if os.path.exists(enc):
        lag = time.time() - os.path.getmtime(enc)
        log(f"[备份] contacts.md.enc 距上次备份 {lag/3600:.1f} 小时")
    if problems:
        log("发现问题:")
        for p in problems:
            log("  - " + p)
        sys.exit(1)
    log("CHECK OK")


def cmd_unlock(args):
    from pykeepass import PyKeePass
    pw = get_master_pw(allow_session=False)
    if not pw:
        log("未输入密码")
        sys.exit(2)
    try:
        PyKeePass(KDBX, password=pw)
    except Exception:
        log("主密码错误")
        sys.exit(3)
    with io.open(SESSION, "w", encoding="utf-8") as f:
        json.dump({"pw": pw, "exp": time.time() + args.ttl}, f)
    try:
        os.chmod(SESSION, 0o600)
    except OSError:
        pass
    log(f"会话已建立，{args.ttl//60} 分钟后自动过期（twin lock 立即清除）")


def cmd_lock(args):
    if os.path.exists(SESSION):
        os.remove(SESSION)
        log("会话已清除")
    else:
        log("无会话")
    if autounlock_pw():
        log("⚠ autounlock 仍开启（无感模式），lock 不影响自动解锁；需硬锁定请 twin autounlock off")


def _find(kp, title):
    tl = title.lower()
    exact = [e for e in kp.entries if e.title and e.title.lower() == tl]
    if exact:
        return exact
    sub = [e for e in kp.entries if e.title and tl in e.title.lower()]
    return sub


def cmd_list(args):
    kp = open_kdbx()
    rows = []
    for e in kp.entries:
        g = "/".join(p.name for p in _path(e)) if hasattr(e, "group") else ""
        if args.group and args.group.lower() not in g.lower():
            continue
        rows.append((g, e.title, e.username or "", "●" if e.password else "○"))
    for g, t, u, has in sorted(rows):
        log(f"  [{g}] {t:44s} user={u or '-':28s} pw={'有' if has=='●' else '无'}")
    log(f"共 {len(rows)} 条")


def _path(entry):
    # pykeepass Entry 没有直接到 root 的路径 API，用 parent 往上爬
    out = []
    g = entry.group
    while g is not None:
        out.append(g)
        g = getattr(g, "parentgroup", None)
    return list(reversed(out))


def cmd_get(args):
    kp = open_kdbx()
    m = _find(kp, args.title)
    if not m:
        log(f"未找到条目: {args.title}（twin list 查看）")
        sys.exit(4)
    if len(m) > 1:
        log("匹配到多个条目，请精确指定:")
        for e in m:
            log("  - " + e.title)
        sys.exit(5)
    e = m[0]
    field = args.field
    val = {"password": e.password, "username": e.username, "url": e.url, "notes": e.notes,
           "title": e.title}.get(field)
    audit_record(f"get\t{e.title}\t{field}")
    if val is None or val == "":
        log(f"(条目『{e.title}』的 {field} 为空)")
        sys.exit(0)
    print(val, flush=True)


def _resolve_group(kp, name):
    for g in kp.root_group.subgroups + [kp.root_group]:
        if g.name == name:
            return g
    return kp.add_group(kp.root_group, name)


def cmd_add(args):
    kp = open_kdbx()
    pw = getpass.getpass("该条目密码/密钥值（直接回车=留空）: ") if sys.stdin.isatty() else (sys.stdin.readline().strip() or "")
    existing = _find(kp, args.title)
    if existing and not args.force:
        log(f"条目已存在: {existing[0].title}（--force 覆盖）")
        sys.exit(6)
    if existing and args.force:
        e = existing[0]
        if args.username:
            e.username = args.username
        if args.url:
            e.url = args.url
        if args.notes:
            e.notes = args.notes
        if pw:
            e.password = pw
        log(f"已更新: {e.title}")
    else:
        g = _resolve_group(kp, args.group)
        kp.add_entry(g, title=args.title, username=args.username or "", password=pw,
                     url=args.url or "", notes=args.notes or "")
        log(f"已新增: {args.title}（组 {g.name}，密值{'已录' if pw else '留空'}）")
    kp.save()
    audit_record(f"{'update' if existing else 'add'}\t{args.title}")


def cmd_rm(args):
    kp = open_kdbx()
    m = _find(kp, args.title)
    if len(m) != 1:
        log("需要唯一匹配，候选: " + ", ".join(e.title for e in m) if m else "未找到")
        sys.exit(4)
    if not args.yes:
        a = input(f"永久删除『{m[0].title}』? 输 yes 确认: ").strip()
        if a != "yes":
            log("已取消")
            return
    kp.delete_entry(m[0])
    kp.save()
    audit_record(f"rm\t{m[0].title}")
    log("已删除")


def cmd_backup(args):
    pw = get_master_pw(allow_session=True, pw_stdin=PW_STDIN)
    if not pw:
        log("备份加密需要主密码")
        sys.exit(2)
    os.makedirs(BACKUP_DEST, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    r = subprocess.run(["openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-iter", "200000", "-salt",
                        "-in", os.path.join(ROOT, "contacts.md"),
                        "-out", os.path.join(BACKUP_DEST, "contacts.md.enc"), "-pass", "stdin"],
                       input=(pw + "\n").encode(), capture_output=True)
    if r.returncode:
        log("加密失败: " + r.stderr.decode()[:200]); sys.exit(7)
    # roundtrip 验证
    r = subprocess.run(["openssl", "enc", "-d", "-aes-256-cbc", "-pbkdf2", "-iter", "200000",
                        "-in", os.path.join(BACKUP_DEST, "contacts.md.enc"), "-pass", "stdin"],
                       input=(pw + "\n").encode(), capture_output=True)
    if r.returncode or not r.stdout.decode("utf-8", "replace").startswith("# L1"):
        log("roundtrip 验证失败！"); sys.exit(7)
    shutil.copy2(KDBX, os.path.join(BACKUP_DEST, f"secrets-{stamp}.kdbx"))
    shutil.copy2(KDBX, os.path.join(BACKUP_DEST, "secrets-latest.kdbx"))
    log("[ok] contacts.md.enc（含roundtrip验证）+ kdbx 副本 x2")
    if args.ssh:
        tar = subprocess.run(["tar", "-C", os.path.expanduser("~"), "-cf", "-", ".ssh"],
                             capture_output=True)
        r = subprocess.run(["openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-iter", "200000", "-salt",
                            "-out", os.path.join(BACKUP_DEST, f"ssh-bundle-{stamp}.tar.enc"), "-pass", "stdin"],
                           input=tar.stdout, capture_output=True)
        log("[ok] ssh-bundle 加密包" if r.returncode == 0 else "[warn] ssh 打包失败（不影响主备份）")
    r = subprocess.run(["git", "-C", ROOT, "add", "-A"], capture_output=True)
    r = subprocess.run(["git", "-C", ROOT, "commit", "-q", "-m", f"backup {stamp}"], capture_output=True, text=True)
    log("[git] " + ("已提交" if r.returncode == 0 else "无变更"))
    audit_record("backup")
    log(f"DONE → {BACKUP_DEST}")


def _load_tokens():
    toks = []
    if os.path.exists(TOKENS):
        for line in io.open(TOKENS, encoding="utf-8"):
            line = line.strip()
            if line and not line.startswith("#"):
                toks.append(line)
    return toks


def cmd_audit(args):
    toks = _load_tokens()
    if not toks:
        log(f"令牌表为空: {TOKENS}")
        sys.exit(1)
    allow = _load_allowlist()
    roots = list(AUDIT_ROOTS) + [("额外", p) for p in (args.path or [])]
    hits, infos = [], []
    for root_name, root in roots:
        if not os.path.isdir(root):
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in {".git", "_eval", "node_modules", ".zcode"}]
            for fn in filenames:
                ext = os.path.splitext(fn)[1].lower()
                full = os.path.join(dirpath, fn)
                key = os.path.normcase(full)
                # 备份区规则：只允许密文与说明
                if root_name == "备份区" and not (fn.endswith((".enc", ".kdbx")) or fn == "README.md"):
                    hits.append((root_name, full, f"非加密文件出现在备份区"))
                if ext not in TEXT_EXT:
                    continue
                try:
                    if os.path.getsize(full) > MAX_FILE:
                        continue
                    t = io.open(full, encoding="utf-8", errors="replace").read()
                except OSError:
                    continue
                for i, tok in enumerate(toks, 1):
                    if tok in t:
                        item = (root_name, full, f"含 L1 令牌 T{i}")
                        (infos if key in allow else hits).append(item)
    report = io.open(os.path.join(ROOT, "inventory", "audit-last.md"), "w", encoding="utf-8")
    report.write(f"# twin audit 报告 {time.strftime('%Y-%m-%d %H:%M')}\n\n")
    for rn, f, why in infos:
        line = f"- [INFO·白名单] [{rn}] {f} — {why}（人工确认过属公开/低风险）"
        log("  " + line)
        report.write(line + "\n")
    if hits:
        log(f"发现 {len(hits)} 处泄露：")
        for rn, f, why in hits:
            line = f"- [{rn}] {f} — {why}"
            log("  " + line)
            report.write(line + "\n")
        report.close()
        audit_record(f"audit\t{len(hits)} hits")
        sys.exit(1)
    log(f"AUDIT CLEAN：同步盘与备份区无 L1 令牌泄露（白名单提示 {len(infos)} 项）")
    report.write("AUDIT CLEAN\n")
    report.close()
    audit_record("audit\tclean")


def cmd_restore(args):
    src, dest = args.dest_dir_backup, args.dest
    enc = os.path.join(src, "contacts.md.enc")
    kdbx_src = os.path.join(src, "secrets-latest.kdbx")
    missing = [p for p in (enc, kdbx_src) if not os.path.exists(p)]
    if missing:
        log("备份区缺文件: " + "; ".join(missing))
        sys.exit(7)
    if os.path.exists(os.path.join(dest, "secrets.kdbx")) and not args.force:
        log(f"目标已存在 {dest}\\secrets.kdbx（--force 覆盖）")
        sys.exit(6)
    os.makedirs(dest, exist_ok=True)
    pw = get_master_pw(allow_session=False, pw_stdin=PW_STDIN)
    if not pw:
        log("需要主密码")
        sys.exit(2)
    r = subprocess.run(["openssl", "enc", "-d", "-aes-256-cbc", "-pbkdf2", "-iter", "200000",
                        "-in", enc, "-out", os.path.join(dest, "contacts.md"), "-pass", "stdin"],
                       input=(pw + "\n").encode(), capture_output=True)
    if r.returncode:
        log("解密失败（主密码错？）"); sys.exit(3)
    head = io.open(os.path.join(dest, "contacts.md"), encoding="utf-8").read(16)
    if not head.startswith("# L1"):
        log("解密产物异常"); sys.exit(7)
    shutil.copy2(kdbx_src, os.path.join(dest, "secrets.kdbx"))
    from pykeepass import PyKeePass
    PyKeePass(os.path.join(dest, "secrets.kdbx"), password=pw)  # 验证
    log(f"RESTORE OK → {dest}")
    log("后续: git clone/拷贝仓库其余文件；SSH 私钥从 ssh-bundle 解包；跑 twin check。")
    audit_record("restore")


def cmd_inject(args):
    """取值但不回显：以 env / stdin 注入目标命令，AI 只见子进程输出。"""
    kp = open_kdbx()
    m = _find(kp, args.title)
    if len(m) != 1:
        log("需要唯一匹配条目: " + ", ".join(e.title for e in m) if m else "未找到")
        sys.exit(4)
    e = m[0]
    val = {"password": e.password, "username": e.username, "url": e.url}.get(args.field)
    if not val:
        log(f"条目『{e.title}』的 {args.field} 为空，无值可注入")
        sys.exit(4)
    audit_record(f"inject\t{e.title}\t{args.field}\t{'env:'+args.env if args.env else 'stdin'}")
    env = dict(os.environ)
    if args.env:
        env[args.env] = val
        r = subprocess.run(args.cmd, env=env)
    else:
        r = subprocess.run(args.cmd, input=val.encode())
    log(f"[inject] {e.title} → {'env ' + args.env if args.env else 'stdin'}，子进程退出码 {r.returncode}")
    sys.exit(r.returncode)


def cmd_register(args):
    """一条龙入库：kdbx 条目 + accounts.md 台账行 + 新 L1 令牌 + audit + backup。"""
    kp = open_kdbx()
    if not sys.stdin.isatty():
        val = sys.stdin.readline().strip()
    else:
        val = getpass.getpass("该条目密码/密钥值（直接回车=留空）: ")
    existing = _find(kp, args.title)
    if existing and not args.force:
        log(f"条目已存在: {existing[0].title}（--force 覆盖）")
        sys.exit(6)
    if existing:
        e = existing[0]
        if args.username: e.username = args.username
        if args.url: e.url = args.url
        if args.notes: e.notes = args.notes
        if val: e.password = val
        log(f"已更新: {e.title}")
    else:
        g = _resolve_group(kp, args.group)
        kp.add_entry(g, title=args.title, username=args.username or "", password=val,
                     url=args.url or "", notes=args.notes or "", tags=(args.tags.split(",") if args.tags else []))
        log(f"已新增: {args.title}（组 {args.group}）")
    kp.save()
    audit_record(f"register\t{args.title}")

    # 联动 1：accounts.md 台账行（幂等：已有同标题行则跳过）
    ap = os.path.join(ROOT, "accounts.md")
    acc = io.open(ap, encoding="utf-8").read()
    row = f"| {args.title.split('（')[0]} | {args.title} | {args.username or '-'} | kdbx『{args.group}』 |"
    if not any(args.title in ln for ln in acc.splitlines()):
        anchor = "## 待办"
        block = f"\n## {args.group}（{time.strftime('%Y-%m-%d')} register 自动追加）\n\n| 平台 | kdbx条目 | 账号 | 凭据位置 |\n|---|---|---|---|\n{row}\n"
        acc = acc.replace(anchor, block.lstrip("\n") + "\n" + anchor) if anchor in acc else acc + block
        io.open(ap, "w", encoding="utf-8").write(acc)
        log("[联动] accounts.md 已加台账行")
    else:
        log("[联动] accounts.md 已有该条目，跳过")

    # 联动 2：新 L1 令牌（用户显式给 --token，逗号分隔；只收非空新值）
    if args.token:
        toks = [t.strip() for t in args.token.split(",") if t.strip()]
        cur = io.open(TOKENS, encoding="utf-8").read()
        add = [t for t in toks if t not in cur]
        if add:
            with io.open(TOKENS, "a", encoding="utf-8") as f:
                for t in add:
                    f.write(t + "\n")
            log(f"[联动] audit-tokens.txt +{len(add)} 令牌")
        else:
            log("[联动] 令牌已存在，跳过")

    # 联动 3：audit + backup（backup 密码来源：会话/autounlock）
    r = subprocess.run([sys.executable, os.path.abspath(__file__), "audit"], capture_output=True, text=True)
    log("[联动] audit: " + (r.stdout.strip().splitlines()[-1] if r.stdout.strip() else f"exit {r.returncode}"))
    pw = _try_session() or autounlock_pw()
    if pw:
        rb = subprocess.run([sys.executable, os.path.abspath(__file__), "backup", "--pw-stdin"],
                            input=(pw + "\n").encode(), capture_output=True)
        log("[联动] backup: " + ("ok" if rb.returncode == 0 else "FAILED"))
    else:
        log("[联动] backup: 无可用解锁方式（会话/autounlock 均无），请稍后手动 twin backup")
    log("REGISTER DONE")


FORM_PAGE = """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>twin · 敏感信息入库</title>
<style>
 body{{font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;background:#10141c;color:#e6e9ef;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}}
 .card{{background:#171d29;border:1px solid #2a3448;border-radius:14px;padding:32px;width:min(420px,92vw)}}
 h1{{font-size:18px;margin:0 0 4px}} .sub{{color:#8b94a7;font-size:12px;margin-bottom:22px}}
 label{{display:block;font-size:12px;color:#aab3c5;margin:14px 0 6px}}
 input{{width:100%;box-sizing:border-box;background:#0d1117;border:1px solid #2a3448;color:#e6e9ef;border-radius:8px;padding:10px 12px;font-size:14px}}
 input:focus{{outline:none;border-color:#4c7dff}}
 .mp{{border-color:#7a4c1f}} button{{margin-top:24px;width:100%;background:#4c7dff;border:0;color:#fff;border-radius:8px;padding:12px;font-size:15px;cursor:pointer}}
 button:hover{{background:#3a68e8}} .ok{{color:#3dd68c}} .err{{color:#ff6b6b;font-size:13px;margin-top:12px}}
 .meta{{color:#5b6478;font-size:11px;margin-top:18px;line-height:1.6}}
</style></head><body><div class="card">
<h1>🔐 {title}</h1><div class="sub">twin 本地入库表单 · 值直接进 secrets.kdbx，不经过任何 AI</div>
<form id="f">
{fields}
{master_field}
<div class="err" id="err"></div>
<button type="submit">加密入库</button>
<div class="meta">提交即焚：本表单一次性使用，数据不经磁盘中转、不回传给 AI 会话。<br>服务仅监听 127.0.0.1。</div>
</form></div>
<script>
f.onsubmit=async e=>{{e.preventDefault();const d={{}};new FormData(f).forEach((v,k)=>d[k]=v);
 const r=await fetch(location.href,{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify(d)}});
 const j=await r.json();
 if(j.ok){{document.querySelector('.card').innerHTML='<h1 class="ok">✅ 已入库</h1><div class="sub">'+j.entry+' → secrets.kdbx（组 {group}）</div><div class="meta">本页面可以关闭了。AI 侧只会收到条目名与状态，不含任何值。</div>';}}
 else{{err.textContent=j.error||'入库失败';}}}};
</script></body></html>"""


BATCH_PAGE = """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>twin · 批量入库</title>
<style>
 body{{font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;background:#10141c;color:#e6e9ef;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0;padding:24px 0}}
 .card{{background:#171d29;border:1px solid #2a3448;border-radius:14px;padding:28px;width:min(560px,94vw)}}
 h1{{font-size:17px;margin:0 0 4px}} .sub{{color:#8b94a7;font-size:12px;margin-bottom:18px}}
 .row{{border:1px solid #232c3e;border-radius:10px;padding:14px;margin-bottom:12px;position:relative}}
 .row .num{{position:absolute;top:-9px;left:12px;background:#232c3e;color:#8b94a7;font-size:11px;border-radius:6px;padding:1px 8px}}
 .del{{position:absolute;top:10px;right:10px;background:none;border:0;color:#5b6478;font-size:15px;cursor:pointer}} .del:hover{{color:#ff6b6b}}
 label{{display:block;font-size:11px;color:#aab3c5;margin:8px 0 4px}}
 input{{width:100%;box-sizing:border-box;background:#0d1117;border:1px solid #2a3448;color:#e6e9ef;border-radius:7px;padding:8px 10px;font-size:13px}}
 input:focus{{outline:none;border-color:#4c7dff}}
 .add{{width:100%;background:none;border:1px dashed #3a465c;color:#8b94a7;border-radius:8px;padding:9px;font-size:13px;cursor:pointer;margin:4px 0 12px}} .add:hover{{color:#e6e9ef;border-color:#4c7dff}}
 button.go{{width:100%;background:#4c7dff;border:0;color:#fff;border-radius:8px;padding:12px;font-size:15px;cursor:pointer}}
 button.go:hover{{background:#3a68e8}} .ok{{color:#3dd68c}} .err{{color:#ff6b6b;font-size:13px;margin-top:10px}}
 .meta{{color:#5b6478;font-size:11px;margin-top:14px;line-height:1.6}}
 .res{{margin-top:14px;font-size:13px}} .res div{{padding:6px 10px;border-radius:7px;margin-bottom:6px;background:#0d1117}}
 .res .r-ok{{color:#3dd68c}} .res .r-bad{{color:#ff6b6b}}
</style></head><body><div class="card">
<h1>🔐 {title}</h1><div class="sub">twin 批量入库 · 全部条目一次提交，值直接进 secrets.kdbx，不经过任何 AI</div>
<div id="rows"></div>
<button class="add" onclick="addRow()">＋ 添加一条</button>
<div class="err" id="err"></div>
<button class="go" onclick="submitAll()">全部加密入库</button>
<div class="res" id="res"></div>
<div class="meta">提交即焚：一次性页面，数据不经磁盘中转、不回传给 AI 会话。服务仅监听 127.0.0.1。</div>
</div>
<script>
const FIELDS = {fields_js};
function addRow() {{
  const n = document.querySelectorAll('.row').length + 1;
  const d = document.createElement('div'); d.className = 'row';
  d.innerHTML = '<span class="num">'+n+'</span><button class="del" title="删除本条" onclick="this.parentElement.remove();renum()">✕</button>'
    + FIELDS.map(f => '<label>'+f[1]+'</label><input type="'+(f[2]?'password':'text')+'" data-name="'+f[0]+'" autocomplete="off">').join('');
  document.getElementById('rows').appendChild(d); renum();
}}
function renum() {{ document.querySelectorAll('.row .num').forEach((s,i)=>s.textContent=i+1); }}
async function submitAll() {{
  const err = document.getElementById('err'); err.textContent='';
  const items = [];
  for (const row of document.querySelectorAll('.row')) {{
    const it = {{}};
    row.querySelectorAll('input').forEach(i => it[i.dataset.name] = i.value.trim());
    if (Object.values(it).some(v => v)) items.push(it);
  }}
  if (!items.length) {{ err.textContent = '至少填写一条'; return; }}
  const r = await fetch(location.href, {{method:'POST', headers:{{'Content-Type':'application/json'}}, body: JSON.stringify({{items}})}});
  const j = await r.json();
  const res = document.getElementById('res');
  if (!j.results) {{ err.textContent = j.error || '提交失败'; return; }}
  let allOk = true;
  res.innerHTML = j.results.map((x,i) => {{
    if (!x.ok) allOk = false;
    return '<div class="'+(x.ok?'r-ok':'r-bad')+'">'+(x.ok?'✅':'❌')+' 第'+(i+1)+'条 · '+x.msg+'</div>';
  }}).join('');
  if (allOk) {{
    document.querySelectorAll('.row, .add, button.go').forEach(e => e.style.display='none');
    res.insertAdjacentHTML('beforeend', '<div class="meta">本页面可以关闭了。AI 侧只会收到条目名与状态。</div>');
  }}
}}
addRow(); addRow();
</script></body></html>"""


def cmd_form(args):
    """本地 Web 表单：AI 只发起与收状态，值从浏览器直达 kdbx。阻塞至提交或超时。"""
    import threading
    import secrets as pysecrets
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from pykeepass import PyKeePass

    token = pysecrets.token_hex(8)
    fields_def = args.field or ["username=用户名", "password=密码"]
    result = {"done": False, "ok": False, "entry": None, "error": None}
    lines = []
    for fd in fields_def:
        name, _, label = fd.partition("=")
        label = label or name
        typ = "password" if any(k in name.lower() for k in ("pass", "secret", "token", "key")) else "text"
        lines.append(f'<label>{label}</label><input type="{typ}" name="{name}" autocomplete="off">')
    auto = autounlock_pw()
    master_field = ('<div class="meta">🔒 自动解锁已开启，无需输入主密码</div>' if auto
                    else '<label>kdbx 主密码（用于本机加密入库）</label><input class="mp" type="password" name="__master__" required autocomplete="off">')
    page = FORM_PAGE.format(title=args.title, fields="".join(lines), master_field=master_field, group=args.group)

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, body, ctype="application/json"):
            self.send_response(code)
            self.send_header("Content-Type", ctype + ("; charset=utf-8" if "json" in ctype or "html" in ctype else ""))
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path == f"/f/{token}":
                self._send(200, page.encode("utf-8"), "text/html")
            else:
                self._send(404, b'{"error":"not found"}')

        def do_POST(self):
            if self.path != f"/f/{token}" or result["done"]:
                self._send(403, b'{"error":"forbidden"}')
                return
            n = int(self.headers.get("Content-Length", 0))
            try:
                import json as _json
                data = _json.loads(self.rfile.read(n).decode("utf-8"))
            except Exception:
                self._send(400, b'{"error":"bad json"}')
                return
            mp = (data.pop("__master__", "") or "").strip() or autounlock_pw() or ""
            if not mp:
                self._send(200, b'{"ok":false,"error":"master password required"}')
                return
            try:
                kp = PyKeePass(KDBX, password=mp)
            except Exception:
                self._send(200, b'{"ok":false,"error":"master password wrong"}')
                return
            title = (data.pop("title", "") or "").strip()[:60] or args.title
            url_v = (data.pop("url", "") or "").strip() or args.url or ""
            uname = data.pop("username", "")
            pwd = ""
            for k in ("password", "pass", "secret", "token", "key", "apikey", "api_key"):
                if data.get(k):
                    pwd = data[k]
                    break
            notes = data.pop("notes", "") or f"via twin form {time.strftime('%Y-%m-%d %H:%M')}"
            g = None
            for grp in kp.root_group.subgroups:
                if grp.name == args.group:
                    g = grp
                    break
            if g is None:
                g = kp.add_group(kp.root_group, args.group)
            if any(e.title == title for e in kp.entries):
                self._send(200, ('{"ok":false,"error":"entry exists: %s"}' % title).encode("utf-8"))
                return
            kp.add_entry(g, title=title, username=uname, password=pwd, url=url_v, notes=notes)
            kp.save()
            result.update(done=True, ok=True, entry=title)
            audit_record(f"form-add\t{title}")
            self._send(200, ('{"ok":true,"entry":"%s"}' % title).encode("utf-8"))

    srv = ThreadingHTTPServer(("127.0.0.1", args.port), H)
    url = f"http://127.0.0.1:{srv.server_address[1]}/f/{token}"
    log(f"[form] {url}  （{args.wait}s 内有效；浏览器打开填写，值直达 kdbx）")
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    deadline = time.time() + args.wait
    try:
        while not result["done"] and time.time() < deadline:
            time.sleep(0.5)
    finally:
        srv.shutdown()
    if result["done"]:
        import json as _j
        log("[result] " + _j.dumps({k: result[k] for k in ("ok", "entry")}, ensure_ascii=False))
        sys.exit(0)
    log("[result] {\"ok\": false, \"error\": \"timeout\"}")
    sys.exit(8)


def cmd_form_batch(args):
    """批量入库页：一页多行条目，一次提交全部进 kdbx。AI 只收逐条状态。"""
    import threading
    import secrets as pysecrets
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from pykeepass import PyKeePass

    token = pysecrets.token_hex(8)
    fields_def = args.field or ["title=平台名", "url=Base URL", "apikey=API Key", "notes=备注"]
    result = {"done": False, "results": None, "error": None}
    fields_js = json.dumps([[n, l, any(k in n.lower() for k in ("pass", "secret", "token", "key"))]
                            for n, l in ((fd.partition("=")[0], fd.partition("=")[2] or fd.partition("=")[0]) for fd in fields_def)],
                           ensure_ascii=False)
    page = BATCH_PAGE.format(title=args.title, fields_js=fields_js)
    mp = autounlock_pw() or ""

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, body):
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8" if body.startswith(b"{") else "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path == f"/f/{token}":
                self._send(200, page.encode("utf-8"))
            else:
                self._send(404, b'{"error":"not found"}')

        def do_POST(self):
            if self.path != f"/f/{token}" or result["done"]:
                self._send(403, b'{"error":"forbidden"}')
                return
            n = int(self.headers.get("Content-Length", 0))
            try:
                data = json.loads(self.rfile.read(n).decode("utf-8"))
            except Exception:
                self._send(400, b'{"error":"bad json"}')
                return
            items = data.get("items") or []
            if not items:
                self._send(200, b'{"error":"no items"}')
                return
            if not mp:
                self._send(200, b'{"error":"autounlock not enabled; use single form or unlock"}')
                return
            try:
                kp = PyKeePass(KDBX, password=mp)
            except Exception:
                self._send(200, b'{"error":"autounlock blob unreadable"}')
                return
            g = None
            for grp in kp.root_group.subgroups:
                if grp.name == args.group:
                    g = grp
                    break
            if g is None:
                g = kp.add_group(kp.root_group, args.group)
            existing = {e.title for e in kp.entries}
            results = []
            for it in items:
                if not isinstance(it, dict):
                    results.append({"ok": False, "msg": "格式错误"})
                    continue
                title = (it.get("title") or "").strip()[:60]
                if not title:
                    results.append({"ok": False, "msg": "缺平台名"})
                    continue
                if title in existing:
                    results.append({"ok": False, "msg": f"{title} 已存在（同名拒绝）"})
                    continue
                pwd = ""
                for k in ("apikey", "api_key", "password", "pass", "secret", "token", "key"):
                    if it.get(k):
                        pwd = it[k]
                        break
                kp.add_entry(g, title=title, username=it.get("username", ""),
                             password=pwd, url=it.get("url", ""), notes=it.get("notes", "") or f"via twin batch form {time.strftime('%Y-%m-%d %H:%M')}")
                existing.add(title)
                results.append({"ok": True, "msg": f"{title} → kdbx『{args.group}』"})
                audit_record(f"form-batch\t{title}")
            if any(r["ok"] for r in results):
                kp.save()
            result.update(done=True, results=results)
            self._send(200, json.dumps({"results": results}, ensure_ascii=False).encode("utf-8"))

    srv = ThreadingHTTPServer(("127.0.0.1", args.port), H)
    url = f"http://127.0.0.1:{srv.server_address[1]}/f/{token}"
    log(f"[form-batch] {url}  （{args.wait}s 内有效；多行填写一次提交）")
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    deadline = time.time() + args.wait
    try:
        while not result["done"] and time.time() < deadline:
            time.sleep(0.5)
    finally:
        srv.shutdown()
    import json as _j
    if result["done"]:
        log("[result] " + _j.dumps({"ok": all(r["ok"] for r in result["results"]), "results": result["results"]}, ensure_ascii=False))
        sys.exit(0)
    log("[result] {\"ok\": false, \"error\": \"timeout\"}")
    sys.exit(8)


def main():
    global PW_STDIN
    if "--pw-stdin" in sys.argv:  # 任一子命令通用的管道密码开关
        PW_STDIN = True
        sys.argv.remove("--pw-stdin")
    inject_cmd = None
    if len(sys.argv) > 1 and sys.argv[1] == "inject":
        # REMAINDER 会吞掉 --env，手动按第一个 "--" 切分
        if "--" in sys.argv[2:]:
            i = sys.argv.index("--", 2)
            inject_cmd = sys.argv[i + 1:]
            sys.argv = sys.argv[:i]
    ap = argparse.ArgumentParser(prog="twin", description="个人数字孪生 CLI")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("check").set_defaults(fn=cmd_check)
    p = sub.add_parser("unlock"); p.add_argument("--ttl", type=int, default=900); p.set_defaults(fn=cmd_unlock)
    sub.add_parser("lock").set_defaults(fn=cmd_lock)
    p = sub.add_parser("autounlock"); p.add_argument("op", choices=["on", "off", "status"]); p.set_defaults(fn=cmd_autounlock)
    p = sub.add_parser("list"); p.add_argument("--group"); p.set_defaults(fn=cmd_list)
    p = sub.add_parser("get"); p.add_argument("title"); p.add_argument("--field", default="password",
        choices=["password", "username", "url", "notes", "title"]); p.set_defaults(fn=cmd_get)
    p = sub.add_parser("add"); p.add_argument("title"); p.add_argument("--username"); p.add_argument("--url")
    p.add_argument("--notes"); p.add_argument("--group", default="网络账号"); p.add_argument("--force", action="store_true")
    p.set_defaults(fn=cmd_add)
    p = sub.add_parser("rm"); p.add_argument("title"); p.add_argument("--yes", action="store_true"); p.set_defaults(fn=cmd_rm)
    p = sub.add_parser("backup"); p.add_argument("--ssh", action="store_true"); p.set_defaults(fn=cmd_backup)
    p = sub.add_parser("audit"); p.add_argument("--path", action="append"); p.set_defaults(fn=cmd_audit)
    p = sub.add_parser("restore"); p.add_argument("dest_dir_backup"); p.add_argument("--dest", default=ROOT)
    p.add_argument("--force", action="store_true"); p.set_defaults(fn=cmd_restore)
    p = sub.add_parser("inject"); p.add_argument("title"); p.add_argument("--field", default="password",
        choices=["password", "username", "url"]); p.add_argument("--env")
    p.set_defaults(fn=cmd_inject)
    p = sub.add_parser("register"); p.add_argument("title"); p.add_argument("--username"); p.add_argument("--url")
    p.add_argument("--notes"); p.add_argument("--group", default="网络账号"); p.add_argument("--tags")
    p.add_argument("--token", help="新 L1 令牌，逗号分隔，自动追加到 audit-tokens.txt")
    p.add_argument("--force", action="store_true"); p.set_defaults(fn=cmd_register)
    p = sub.add_parser("form"); p.add_argument("title"); p.add_argument("--group", default="网络账号")
    p.add_argument("--field", action="append", help="字段定义 name=标签，可多次")
    p.add_argument("--mode", choices=["single", "batch"], default="single")
    p.add_argument("--url", default=""); p.add_argument("--port", type=int, default=8340)
    p.add_argument("--wait", type=int, default=600)
    p.set_defaults(fn=lambda a: cmd_form_batch(a) if a.mode == "batch" else cmd_form(a))
    args = ap.parse_args()
    if args.cmd == "inject":
        if not inject_cmd:
            log("inject 需要目标命令：twin inject <条目> --env VAR -- <命令> [参数...]")
            sys.exit(1)
        args.cmd = inject_cmd
    args.fn(args)


if __name__ == "__main__":
    main()
