"""navi-labkit core - home-lab target manager for Apex.

Downloads, verifies, runs and retires deliberately vulnerable practice
targets (VulnHub VMs, Vulhub Docker environments) on an ISOLATED lab
segment. The lab law, enforced in code, not just in docs:

  * VulnHub VMs run on a host-only VirtualBox segment (192.168.56.0/24).
    They never touch the home LAN unless the operator explicitly opts a
    single box in with --bridge-ok, per box, per start.
  * Vulhub environments are rebound to 127.0.0.1 before they start; a
    compose file that publishes on a LAN address, uses long-syntax port
    mappings this chip cannot verify, or asks for host networking is
    REFUSED, loudly.
  * Downloads are verified against the catalog's published checksums
    before import. A mismatch refuses and deletes the file.

Stdlib only. No listeners. Catalog data is data - never executed.
Remote lab hosts are driven over the system ssh with the operator's
existing setup; no credentials are stored anywhere.
"""

import hashlib
import io
import json
import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
import time
from contextlib import redirect_stdout
from datetime import datetime

from .catalog import TARGETS

VERSION = "1.0.0"
LAB_CIDR = "192.168.56.0/24"
LAB_IP = "192.168.56.1"
LAB_NETMASK = "255.255.255.0"
DHCP_SERVER_IP = "192.168.56.100"
DHCP_LOWER = "192.168.56.101"
DHCP_UPPER = "192.168.56.220"
DEFAULT_LAB_HOST = "neoarcadia"
VULHUB_REPO_URL = "https://github.com/vulhub/vulhub"
CASE_SEVERITIES = ["critical", "high", "medium", "low", "info"]

SOURCE_LABEL = {
    "vulnhub": "VulnHub",
    "vulhub": "Vulhub",
    "metasploitable": "Metasploitable",
    "local": "Local",
}

SLEEP = time.sleep  # patched out by the self-test


class LabError(Exception):
    """A plain, loud refusal or failure - printed as `error: ...`."""


# --------------------------------------------------------------------------
# Executors: everything the chip does to a machine goes through one of
# these, so the self-test can stub the whole world.

class Result:
    def __init__(self, rc, out="", err=""):
        self.rc = rc
        self.out = out or ""
        self.err = err or ""

    @property
    def ok(self):
        return self.rc == 0

    def tail(self, n=3):
        text = (self.err or self.out).strip().splitlines()
        return " | ".join(text[-n:]) if text else f"exit code {self.rc}"


class LocalExecutor:
    label = "local"
    is_local = True

    def run(self, argv, cwd=None, timeout=600, stdin=None):
        try:
            proc = subprocess.run(
                [str(a) for a in argv], cwd=cwd, timeout=timeout,
                input=stdin, capture_output=True, text=True)
            return Result(proc.returncode, proc.stdout, proc.stderr)
        except FileNotFoundError:
            return Result(127, "", f"{argv[0]}: not found")
        except subprocess.TimeoutExpired:
            return Result(124, "", f"timed out after {timeout}s: {argv[0]}")

    def home(self):
        return os.path.expanduser("~")


class SshExecutor:
    """Drives a lab host over the operator's existing ssh setup.

    Uses the system ssh binary with the operator's own config/keys/agent -
    the chip stores no credentials and accepts no passwords.
    """

    is_local = False

    def __init__(self, host):
        self.host = host
        self.label = host
        self._home = None

    def run(self, argv, cwd=None, timeout=600, stdin=None):
        remote = shlex.join([str(a) for a in argv])
        if cwd:
            remote = f"cd {shlex.quote(str(cwd))} && {remote}"
        full = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
                self.host, remote]
        try:
            proc = subprocess.run(full, timeout=timeout, input=stdin,
                                  capture_output=True, text=True)
            return Result(proc.returncode, proc.stdout, proc.stderr)
        except FileNotFoundError:
            return Result(127, "", "ssh: not found")
        except subprocess.TimeoutExpired:
            return Result(124, "", f"ssh to {self.host} timed out")

    def home(self):
        if self._home is None:
            res = self.run(["sh", "-c", "echo $HOME"], timeout=30)
            self._home = res.out.strip() or "/home/" + self.host
        return self._home


class FakeExecutor:
    """Self-test executor: a scripted handler answers every command.

    Presents as non-local so hashing, reads and writes all flow through
    the handler (md5sum / cat / sh) exactly as they would over ssh.
    """

    is_local = False

    def __init__(self, handler, label="fakehost"):
        self.handler = handler
        self.label = label
        self.calls = []

    def run(self, argv, cwd=None, timeout=600, stdin=None):
        argv = [str(a) for a in argv]
        self.calls.append(argv)
        out = self.handler(argv, cwd, stdin)
        if isinstance(out, Result):
            return out
        rc, o, e = out
        return Result(rc, o, e)

    def home(self):
        return "/fakehome"


# --------------------------------------------------------------------------
# Paths, config, state (state always lives on the operator's machine)

def state_dir():
    root = os.environ.get("NAVI_LABKIT_HOME") or os.path.join(
        os.path.expanduser("~"), "navi-labkit")
    os.makedirs(root, exist_ok=True)
    return root


def _json_read(path, default):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return default


def load_config():
    return _json_read(os.path.join(state_dir(), "labkit.json"), {})


def load_state():
    state = _json_read(os.path.join(state_dir(), "instances.json"),
                       {"instances": {}})
    state.setdefault("instances", {})
    return state


def save_state(state):
    path = os.path.join(state_dir(), "instances.json")
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(state, fh, indent=2, sort_keys=True)
    os.replace(tmp, path)


def store_root(ex):
    return ex.home().rstrip("/") + "/navi-labkit/store"


def slug_of(target_id):
    return target_id.split("/", 1)[-1]


# --------------------------------------------------------------------------
# Catalog helpers + the provenance pill

def find_target(target_id):
    for entry in TARGETS:
        if entry["id"] == target_id:
            return entry
    return None


def catalog_pill(entry):
    """The provenance pill for a catalog entry: [Source] Name."""
    return f"[{SOURCE_LABEL[entry['source']]}] {entry['name']}"


def instance_pill(rec):
    """Running-instance pill: source - host - IP - state, per the spec."""
    label = SOURCE_LABEL.get(rec.get("source"), rec.get("source", "?"))
    line = (f"[{label}] {rec['name']} · host {rec.get('host_label', '?')} · "
            f"ip {rec.get('ip') or 'pending'} · {rec.get('state', '?')}")
    if rec.get("bridged"):
        line += " · BRIDGED (opted in)"
    return line


# --------------------------------------------------------------------------
# Detection - honest capability reporting, never faked

def _first_line(res):
    if res.ok and res.out.strip():
        return res.out.strip().splitlines()[0].strip()
    return None


def detect_on(ex):
    """Probe one host (through its executor) for the lab toolchain."""
    info = {"host": ex.label}
    info["os"] = _first_line(ex.run(["uname", "-srm"], timeout=30)) \
        if not ex.is_local else f"{platform.system()} {platform.machine()}"
    info["docker"] = _first_line(ex.run(["docker", "--version"], timeout=30))
    info["compose"] = _first_line(
        ex.run(["docker", "compose", "version"], timeout=30))
    info["vbox"] = _first_line(ex.run(["VBoxManage", "--version"], timeout=30))
    info["git"] = _first_line(ex.run(["git", "--version"], timeout=30))
    info["curl"] = _first_line(ex.run(["curl", "--version"], timeout=30))
    if ex.is_local:
        info["ram_gib"] = _local_ram_gib()
    else:
        res = ex.run(["sh", "-c",
                      "grep MemTotal /proc/meminfo 2>/dev/null || "
                      "sysctl -n hw.memsize 2>/dev/null"], timeout=30)
        info["ram_gib"] = _parse_ram(res.out)
    return info


def _parse_ram(text):
    m = re.search(r"MemTotal:\s+(\d+)\s*kB", text or "")
    if m:
        return round(int(m.group(1)) / 1048576, 1)
    m = re.search(r"^\s*(\d{9,})\s*$", (text or "").strip())
    if m:
        return round(int(m.group(1)) / 1073741824, 1)
    return None


def _local_ram_gib():
    try:
        with open("/proc/meminfo", encoding="utf-8") as fh:
            return _parse_ram(fh.read())
    except OSError:
        pass
    try:
        out = subprocess.run(["sysctl", "-n", "hw.memsize"],
                             capture_output=True, text=True, timeout=10)
        return _parse_ram(out.stdout)
    except (OSError, subprocess.SubprocessError):
        return None


def ssh_reachable(host):
    try:
        proc = subprocess.run(
            ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=6",
             host, "true"], capture_output=True, text=True, timeout=20)
        return proc.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


EXECUTOR_FACTORY = None  # self-test hook; production leaves this None


def resolve_lab(opts):
    """Pick the executor for VM/Docker work: (--host | config | auto).

    Auto = the configured lab host, else NeoArcadia over ssh when it
    answers, else this machine. Returns (executor, note_or_None).
    """
    if EXECUTOR_FACTORY is not None:
        return EXECUTOR_FACTORY(opts), None
    cfg = load_config()
    choice = opts.get("host") or cfg.get("lab_host") or "auto"
    if choice == "local":
        return LocalExecutor(), None
    name = choice if choice != "auto" else (
        cfg.get("lab_host_name") or DEFAULT_LAB_HOST)
    if ssh_reachable(name):
        return SshExecutor(name), None
    if choice == "auto":
        return LocalExecutor(), (
            f"note: lab host {name} did not answer over ssh - "
            "working on this machine instead. Set one with "
            "navi-labkit --host <name>, or 'lab_host' in labkit.json.")
    raise LabError(
        f"lab host {name} is not reachable over ssh (BatchMode). "
        "Check the host name and your ssh setup - the chip uses your "
        "existing ssh config and keys and stores no credentials.")


def maybe_ram_warning(ex, entry):
    if not ex.is_local or entry.get("kind") != "vm":
        return
    ram = _local_ram_gib()
    if ram is not None and ram < 12:
        print(f"warning: this machine has {ram} GiB of RAM - running a "
              "target VM locally will be tight next to Apex. The lab "
              "host (NeoArcadia) is the better home for VMs; local is "
              "the fallback.")


# --------------------------------------------------------------------------
# shelf / hosts

def cmd_shelf(opts):
    print("navi-labkit shelf - bundled starter catalog "
          "(VulnHub data verified from vulnhub.com entry pages and "
          "Vulhub data from the vulhub/vulhub repo, 2026-11-11)")
    print()
    by_source = {}
    for entry in TARGETS:
        by_source.setdefault(entry["source"], []).append(entry)
    for source in ("vulnhub", "vulhub", "metasploitable", "local"):
        entries = by_source.get(source)
        if source == "metasploitable":
            print("Metasploitable: joins the shelf in a later build - "
                  "the pill already knows the source.")
            print()
            continue
        if not entries:
            continue
        if source == "vulnhub":
            print("VulnHub - downloadable VMs (VirtualBox):")
        elif source == "vulhub":
            print("Vulhub - Docker Compose environments:")
        else:
            print(f"{SOURCE_LABEL[source]}:")
        for e in entries:
            if e["kind"] == "vm":
                print(f"  {catalog_pill(e)} - {e['difficulty']} - "
                      f"{e['size_human']}")
                print(f"      {e['id']} - {e['objective']}")
            else:
                ports = ", ".join(str(p) for p in e["ports"])
                print(f"  {catalog_pill(e)} - {e['difficulty']}")
                print(f"      {e['id']} - image {e['image']} - "
                      f"ports {ports} (rebound to 127.0.0.1)")
        print()
    print("Lab law: VulnHub VMs run on the isolated host-only segment "
          f"{LAB_CIDR}; Vulhub ports bind 127.0.0.1 only. A target "
          "touches the home LAN only if you opt that one box in with "
          "--bridge-ok.")
    print("Grab one:  navi-labkit grab vulnhub/dc-1")


def cmd_hosts(opts):
    print("navi-labkit hosts - what each machine can actually do")
    local = detect_on(LocalExecutor())
    _print_detect("this machine", local)
    cfg = load_config()
    name = opts.get("host") or cfg.get("lab_host_name") or DEFAULT_LAB_HOST
    if ssh_reachable(name):
        _print_detect(f"{name} (ssh)", detect_on(SshExecutor(name)))
    else:
        print(f"  lab host {name}: not reachable over ssh right now "
              "(BatchMode probe failed - no credentials are stored, "
              "your ssh config/keys/agent are used as-is)")
    print("VM targets default to the lab host when it answers; "
          "this machine is the fallback (with a RAM warning when small).")


def _print_detect(title, info):
    def yn(value):
        return value if value else "not found"
    ram = f"{info['ram_gib']} GiB" if info.get("ram_gib") else "unknown"
    print(f"  {title}: {info.get('os') or 'unknown os'} - ram {ram}")
    print(f"    docker {yn(info.get('docker'))} · compose "
          f"{yn(info.get('compose'))} · virtualbox {yn(info.get('vbox'))}"
          f" · git {yn(info.get('git'))} · curl {yn(info.get('curl'))}")


# --------------------------------------------------------------------------
# Downloads + mandatory checksum verification

def _hash_local(path, algo):
    h = hashlib.new(algo)
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def hash_on(ex, path, algo):
    if ex.is_local:
        return _hash_local(path, algo)
    res = ex.run([algo + "sum", path], timeout=1200)
    if not res.ok:
        raise LabError(f"could not hash {path} on {ex.label}: "
                       f"{res.tail()}")
    return res.out.strip().split()[0].lower()


def verify_artifact(ex, path, entry):
    """Verify a downloaded file against the published checksums.

    Every checksum the catalog publishes for the entry (MD5 and/or SHA1)
    must match. Any mismatch REFUSES: the file is deleted on the spot.
    """
    published = {}
    for algo in ("md5", "sha1"):
        if entry.get(algo):
            published[algo] = entry[algo].lower()
    if not published:
        raise LabError(
            f"{entry['id']}: the catalog publishes no checksum for this "
            "target, so it cannot be verified - refusing to import it.")
    for algo, want in published.items():
        got = hash_on(ex, path, algo)
        if got != want:
            ex.run(["rm", "-f", path], timeout=60)
            raise LabError(
                f"CHECKSUM MISMATCH for {entry['name']} ({algo}): "
                f"published {want}, downloaded file hashes to {got}. "
                "The file was deleted and NOT imported. Re-grab to try "
                "again; if it keeps mismatching, do not use the mirror.")
    return sorted(published)


def download_on(ex, url, dest, entry):
    ex.run(["mkdir", "-p", dest.rsplit("/", 1)[0]], timeout=60)
    probe = ex.run(["sh", "-c", "command -v curl || command -v wget"],
                   timeout=30)
    tool = probe.out.strip().split("/")[-1] if probe.ok else None
    tmp = dest + ".part"
    if tool == "curl":
        res = ex.run(["curl", "-fL", "--retry", "2", "--connect-timeout",
                      "20", "-o", tmp, url], timeout=3600)
    elif tool == "wget":
        res = ex.run(["wget", "-q", "-O", tmp, url], timeout=3600)
    else:
        raise LabError(
            f"neither curl nor wget is available on {ex.label} - "
            f"download {entry['filename']} on a machine that has one "
            "and use: navi-labkit grab " + entry["id"] + " --file <path>")
    if not res.ok:
        ex.run(["rm", "-f", tmp], timeout=60)
        raise LabError(f"download of {url} failed on {ex.label}: "
                       f"{res.tail()}")
    ex.run(["mv", tmp, dest], timeout=120)


# --------------------------------------------------------------------------
# VirtualBox machinery - the lab segment is created, pinned, and checked

def _vbox(ex, *args, timeout=300):
    return ex.run(["VBoxManage", *args], timeout=timeout)


def _require_vbox(ex):
    if not _vbox(ex, "--version", timeout=30).ok:
        raise LabError(
            f"VirtualBox (VBoxManage) is not available on {ex.label}. "
            "Install VirtualBox there, or point the chip at the lab "
            "host with --host.")


def parse_hostonlyifs(text):
    adapters = []
    name = ip = None
    for line in (text or "").splitlines():
        if line.startswith("Name:"):
            if name:
                adapters.append((name, ip))
            name, ip = line.split(":", 1)[1].strip(), None
        elif line.startswith("IPAddress:"):
            ip = line.split(":", 1)[1].strip()
    if name:
        adapters.append((name, ip))
    return adapters


def _ip_in_lab(ip):
    try:
        parts = [int(p) for p in ip.split(".")]
        return parts[:3] == [192, 168, 56]
    except (ValueError, AttributeError):
        return False


def ensure_lab_adapter(ex):
    """Guarantee a host-only adapter on 192.168.56.0/24 with DHCP.

    Returns the adapter name. Raises LabError if it cannot be done -
    a target never starts on an unverified network.
    """
    res = _vbox(ex, "list", "hostonlyifs", timeout=60)
    if not res.ok:
        raise LabError(f"cannot list host-only adapters on {ex.label}: "
                       f"{res.tail()}")
    adapters = parse_hostonlyifs(res.out)
    for name, ip in adapters:
        if ip and _ip_in_lab(ip):
            return name
    names = [n for n, _ in adapters]
    adapter = "vboxnet0"
    if adapter not in names:
        res = _vbox(ex, "hostonlyif", "create", timeout=120)
        if not res.ok:
            raise LabError(f"cannot create host-only adapter: "
                           f"{res.tail()}")
        res = _vbox(ex, "list", "hostonlyifs", timeout=60)
        names = [n for n, _ in parse_hostonlyifs(res.out)]
        if adapter not in names and names:
            adapter = names[0]
    res = _vbox(ex, "hostonlyif", "ipconfig", adapter, "--ip", LAB_IP,
                "--netmask", LAB_NETMASK, timeout=120)
    if not res.ok:
        raise LabError(f"cannot address {adapter} as {LAB_IP}: "
                       f"{res.tail()}")
    dhcp = _vbox(ex, "list", "dhcpservers", timeout=60).out
    if f"HostInterfaceNetworking-{adapter}" not in dhcp:
        _vbox(ex, "dhcpserver", "add", "--ifname", adapter, "--ip",
              DHCP_SERVER_IP, "--netmask", LAB_NETMASK, "--lowerip",
              DHCP_LOWER, "--upperip", DHCP_UPPER, "--enable", timeout=120)
    else:
        _vbox(ex, "dhcpserver", "modify", "--ifname", adapter, "--enable",
              timeout=120)
    res = _vbox(ex, "list", "hostonlyifs", timeout=60)
    for name, ip in parse_hostonlyifs(res.out):
        if name == adapter and ip and _ip_in_lab(ip):
            return adapter
    raise LabError(
        f"host-only adapter {adapter} did not come up on {LAB_CIDR} - "
        "refusing to start any target on an unverified network.")


def showvminfo(ex, vm):
    res = _vbox(ex, "showvminfo", vm, "--machinereadable", timeout=60)
    if not res.ok:
        raise LabError(f"cannot inspect VM {vm}: {res.tail()}")
    info = {}
    for line in res.out.splitlines():
        m = re.match(r'^([A-Za-z0-9_]+)="(.*)"$', line.strip())
        if m:
            info[m.group(1)] = m.group(2)
    return info


def _bridged_adapter(ex):
    res = _vbox(ex, "list", "bridgedifs", timeout=60)
    for name, _ in parse_hostonlyifs(res.out):
        return name
    raise LabError("no bridged adapter found on this host - cannot "
                   "honour the --bridge-ok opt-in.")


def enforce_lab_network(ex, vm, bridge_ok):
    """The law, at the code path every start goes through.

    bridge_ok=True  -> pin NIC1 to bridged, loudly, for this box only.
    bridge_ok=False -> a VM found configured for bridged networking is
                       REFUSED (never silently re-pinned at start time);
                       anything else is pinned to the host-only lab
                       adapter before boot.
    Returns True if the VM ends up bridged.
    """
    info = showvminfo(ex, vm)
    nic = info.get("nic1", "none")
    if bridge_ok:
        adapter = _bridged_adapter(ex)
        if nic != "bridged" or info.get("bridgeadapter1") != adapter:
            res = _vbox(ex, "modifyvm", vm, "--nic1", "bridged",
                        "--bridgeadapter1", adapter, timeout=120)
            if not res.ok:
                raise LabError(f"cannot bridge {vm}: {res.tail()}")
        return True
    if nic == "bridged":
        raise LabError(
            f"REFUSED: {vm} is configured for BRIDGED networking, which "
            "would put a deliberately vulnerable box on the home LAN. "
            "LabKit never starts a bridged target without the explicit "
            "per-box opt-in: navi-labkit up <target> --bridge-ok (after "
            "re-import, grab pins it to the lab segment automatically).")
    adapter = ensure_lab_adapter(ex)
    if nic != "hostonly" or info.get("hostonlyadapter1") != adapter:
        res = _vbox(ex, "modifyvm", vm, "--nic1", "hostonly",
                    "--hostonlyadapter1", adapter, "--cableconnected1",
                    "on", timeout=120)
        if not res.ok:
            raise LabError(f"cannot pin {vm} to the lab segment: "
                           f"{res.tail()}")
        print(f"  network: pinned to host-only lab segment {LAB_CIDR} "
              f"({adapter})")
    return False


def discover_ip(ex, vm, entry):
    """Best-effort target IP: static note, guest property, DHCP lease,
    neighbour table. None of the starter VulnHub boxes needs Guest
    Additions for the lease/neighbour paths."""
    if entry.get("static_ip"):
        return entry["static_ip"]
    res = _vbox(ex, "guestproperty", "get", vm,
                "/VirtualBox/GuestInfo/Net/0/V4/IP", timeout=60)
    m = re.search(r"Value:\s+(\d+\.\d+\.\d+\.\d+)", res.out or "")
    if m and _ip_in_lab(m.group(1)):
        return m.group(1)
    mac = showvminfo(ex, vm).get("macaddress1", "")
    mac_colon = ":".join(mac[i:i + 2] for i in range(0, 12, 2)).lower() \
        if len(mac) == 12 else ""
    if mac_colon:
        leases = ex.run(
            ["sh", "-c",
             "cat ~/.config/VirtualBox/*.leases 2>/dev/null"],
            timeout=60).out
        for block in re.split(r"(?=lease\s)", leases or ""):
            if mac_colon in block.lower():
                m = re.search(r"lease\s+(\d+\.\d+\.\d+\.\d+)", block)
                if m and _ip_in_lab(m.group(1)):
                    return m.group(1)
        neigh = ex.run(["ip", "neigh", "show"], timeout=60).out
        for line in (neigh or "").splitlines():
            if mac_colon in line.lower():
                m = re.match(r"(\d+\.\d+\.\d+\.\d+)", line)
                if m and _ip_in_lab(m.group(1)):
                    return m.group(1)
    return None


def import_vm(ex, artifact_path, entry):
    """Import an OVA/OVF (extracting zip artifacts first). Returns the
    VirtualBox VM name. Network re-pin + pristine snapshot included."""
    slug = slug_of(entry["id"])
    vm_name = f"labkit-{slug}"
    existing = _vbox(ex, "list", "vms", timeout=60).out
    if f'"{vm_name}"' in existing:
        return vm_name
    src = artifact_path
    if entry.get("archive") == "zip":
        out_dir = artifact_path.rsplit(".", 1)[0] + "-extracted"
        ex.run(["mkdir", "-p", out_dir], timeout=60)
        res = ex.run(["unzip", "-o", "-q", artifact_path, "-d", out_dir],
                     timeout=900)
        if not res.ok:
            res = ex.run(["python3", "-m", "zipfile", "-e", artifact_path,
                          out_dir], timeout=900)
        if not res.ok:
            raise LabError(f"cannot extract {entry['filename']}: "
                           f"{res.tail()}")
        listing = ex.run(["ls", out_dir], timeout=60).out.split()
        pick = next((f for f in listing if f.lower().endswith(".ova")),
                    None) or next(
                        (f for f in listing if f.lower().endswith(".ovf")),
                        None)
        if not pick:
            if any(f.lower().endswith(".vmx") for f in listing):
                raise LabError(
                    f"{entry['filename']} contains VMware-format files "
                    f"({', '.join(listing)}), which VirtualBox cannot "
                    "import. Convert the disk with qemu-img or run it "
                    "under VMware - LabKit will not guess.")
            raise LabError(
                f"no .ova/.ovf found inside {entry['filename']} "
                f"(found: {', '.join(listing) or 'nothing'})")
        src = out_dir + "/" + pick
    res = _vbox(ex, "import", src, "--vsys", "0", "--vmname", vm_name,
                timeout=1800)
    if not res.ok:
        raise LabError(f"VirtualBox import of {entry['name']} failed: "
                       f"{res.tail()}")
    return vm_name


# --------------------------------------------------------------------------
# Vulhub machinery - compose files are sanitized before they ever run

_PORT_RE = re.compile(
    r'^(\s*-\s*)"?((?:\d{1,3}\.){3}\d{1,3}:)?(\d+):(\d+)'
    r'((?:/tcp|/udp)?)"?\s*$')


def sanitize_compose(text, entry):
    """Rebind every published port to 127.0.0.1 - or refuse, loudly.

    Refusals: long-syntax mappings (bind address unverifiable), binds on
    a specific non-loopback/non-lab address, host networking, and any
    port-looking line this parser cannot account for.
    Returns (sanitized_text, [host_ports]).
    """
    out_lines = []
    ports = []
    for line in text.splitlines():
        stripped = line.strip()
        if "network_mode" in stripped and "host" in stripped:
            raise LabError(
                f"{entry['id']}: compose requests host networking - "
                "refused. Host networking would put a vulnerable "
                "environment on every interface this machine has.")
        if stripped.startswith("-") and (
                ":" in stripped or "target" in stripped):
            if "target" in stripped or "published" in stripped:
                raise LabError(
                    f"{entry['id']}: long-syntax port mapping "
                    f"({stripped!r}) - refused, because its bind "
                    "address cannot be verified by this chip.")
            m = _PORT_RE.match(line)
            if not m:
                raise LabError(
                    f"{entry['id']}: unrecognized port mapping "
                    f"({stripped!r}) - refused rather than guessed.")
            indent, ip_part, host_port, cont_port, proto = m.groups()
            if ip_part:
                ip = ip_part.rstrip(":")
                if ip != "127.0.0.1" and not _ip_in_lab(ip):
                    raise LabError(
                        f"{entry['id']}: compose publishes on {ip} - "
                        "refused. LabKit binds Vulhub ports to "
                        "127.0.0.1 only.")
                out_lines.append(line)
            else:
                out_lines.append(
                    f'{indent}"127.0.0.1:{host_port}:{cont_port}{proto}"')
            ports.append(int(host_port))
            continue
        out_lines.append(line)
    return "\n".join(out_lines) + "\n", ports


def _compose_project(entry):
    return "labkit-" + re.sub(r"[^a-z0-9-]+", "-", slug_of(entry["id"]))


def _env_workdir(ex, entry):
    return store_root(ex) + "/envs/" + slug_of(entry["id"])


def _read_remote_text(ex, path):
    if ex.is_local:
        try:
            with open(path, encoding="utf-8") as fh:
                return fh.read()
        except OSError as exc:
            raise LabError(f"cannot read {path}: {exc}")
    res = ex.run(["cat", path], timeout=60)
    if not res.ok:
        raise LabError(f"cannot read {path} on {ex.label}: {res.tail()}")
    return res.out


def _write_remote_text(ex, path, text):
    ex.run(["mkdir", "-p", path.rsplit("/", 1)[0]], timeout=60)
    if ex.is_local:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        return
    res = ex.run(["sh", "-c", f"cat > {shlex.quote(path)}"], stdin=text,
                 timeout=60)
    if not res.ok:
        raise LabError(f"cannot write {path} on {ex.label}: {res.tail()}")


def _require_docker(ex):
    if not ex.run(["docker", "--version"], timeout=30).ok:
        raise LabError(
            f"Docker is not available on {ex.label}. Install Docker "
            "there, or point the chip at a host that has it (--host).")
    if not ex.run(["docker", "compose", "version"], timeout=30).ok:
        raise LabError(
            f"docker compose (v2 plugin) is not available on "
            f"{ex.label} - Vulhub environments are driven with it.")


def _compose(ex, entry, *args, timeout=1200):
    workdir = _env_workdir(ex, entry)
    gen = workdir + "/docker-compose.labkit.yml"
    return ex.run(["docker", "compose", "-f", gen, "-p",
                   _compose_project(entry), *args], cwd=workdir,
                  timeout=timeout)


def prepare_env(ex, entry):
    """Write the sanitized compose file for a Vulhub env. Idempotent."""
    repo_dir = store_root(ex) + "/vulhub-repo"
    src = repo_dir + "/" + entry["path"] + "/docker-compose.yml"
    text = _read_remote_text(ex, src)
    sanitized, ports = sanitize_compose(text, entry)
    workdir = _env_workdir(ex, entry)
    gen = workdir + "/docker-compose.labkit.yml"
    _write_remote_text(ex, gen, sanitized)
    return gen, ports


# --------------------------------------------------------------------------
# grab / up / down / kill / reset / status

def _get_rec(state, target_id):
    return state["instances"].get(target_id)


def _put_rec(state, rec):
    state["instances"][rec["id"]] = rec
    save_state(state)


def _entry_or_die(target_id):
    entry = find_target(target_id)
    if not entry:
        known = ", ".join(e["id"] for e in TARGETS)
        raise LabError(f"unknown target {target_id!r}. On the shelf: "
                       f"{known}")
    return entry


def cmd_grab(opts, target_id):
    entry = _entry_or_die(target_id)
    ex, note = resolve_lab(opts)
    if note:
        print(note)
    maybe_ram_warning(ex, entry)
    state = load_state()
    rec = _get_rec(state, target_id) or {
        "id": target_id, "name": entry["name"], "source": entry["source"],
        "kind": entry["kind"], "state": "shelf", "host_label": ex.label,
        "ip": None, "bridged": False, "started_at": None}
    rec["host_label"] = ex.label

    if entry["kind"] == "docker":
        _require_docker(ex)
        if not ex.run(["git", "--version"], timeout=30).ok:
            raise LabError(f"git is not available on {ex.label} - "
                           "Vulhub environments are grabbed by cloning "
                           f"{VULHUB_REPO_URL}.")
        repo_dir = store_root(ex) + "/vulhub-repo"
        have = ex.run(["test", "-d", repo_dir + "/.git"], timeout=30)
        if not have.ok:
            print(f"cloning Vulhub (shallow) onto {ex.label} ...")
            res = ex.run(["git", "clone", "--depth", "1",
                          VULHUB_REPO_URL, repo_dir], timeout=1800)
            if not res.ok:
                raise LabError(f"git clone of Vulhub failed: "
                               f"{res.tail()}")
        env_dir = repo_dir + "/" + entry["path"]
        check = ex.run(["test", "-f", env_dir + "/docker-compose.yml"],
                       timeout=30)
        if not check.ok:
            raise LabError(
                f"{entry['id']}: {entry['path']}/docker-compose.yml not "
                "found in the Vulhub clone - the upstream repo may have "
                "moved it. Nothing was changed.")
        prepare_env(ex, entry)
        rec.update(state="grabbed", artifact=env_dir)
        _put_rec(state, rec)
        print(f"grabbed {catalog_pill(entry)} on {ex.label} "
              f"({entry['image']}, ports rebound to 127.0.0.1 at start)")
        print(f"  up: navi-labkit up {target_id}")
        return

    # VM targets
    _require_vbox(ex)
    slug = slug_of(target_id)
    art_dir = store_root(ex) + "/vulnhub/" + slug
    dest = art_dir + "/" + entry["filename"]
    local_file = opts.get("file")
    if local_file:
        src = os.path.expanduser(local_file)
        if not os.path.isfile(src):
            raise LabError(f"--file {local_file} does not exist here.")
        if ex.is_local:
            ex.run(["mkdir", "-p", art_dir], timeout=60)
            if os.path.abspath(src) != os.path.abspath(dest):
                shutil.copyfile(src, dest)
        else:
            raise LabError(
                "--file names a file on this machine, but the lab host "
                f"is {ex.label}. Copy it to {dest} on that host first "
                "(scp), then grab without --file.")
        print(f"using local file {src}")
    else:
        have = ex.run(["test", "-f", dest], timeout=30)
        if not have.ok:
            print(f"downloading {entry['filename']} "
                  f"({entry['size_human']}) from VulnHub mirror to "
                  f"{ex.label} ...")
            download_on(ex, entry["mirror"], dest, entry)
        else:
            print(f"already on the shelf at {dest} - verifying.")
    algos = verify_artifact(ex, dest, entry)
    print(f"  checksum verified ({' + '.join(a.upper() for a in algos)}"
          " matches the published value)")
    vm_name = import_vm(ex, dest, entry)
    rec["vm_name"] = vm_name
    adapter = ensure_lab_adapter(ex)
    info = showvminfo(ex, vm_name)
    if info.get("nic1") == "bridged":
        print("  note: this box SHIPS configured for bridged networking "
              "- re-pinning it to the lab segment now, before any boot.")
    res = _vbox(ex, "modifyvm", vm_name, "--nic1", "hostonly",
                "--hostonlyadapter1", adapter, "--cableconnected1", "on",
                timeout=120)
    if not res.ok:
        raise LabError(f"cannot pin {vm_name} to the lab segment: "
                       f"{res.tail()}")
    snap = _vbox(ex, "snapshot", vm_name, "list", timeout=60).out
    if "labkit-pristine" not in snap:
        res = _vbox(ex, "snapshot", vm_name, "take", "labkit-pristine",
                    "--pause", timeout=600)
        if res.ok:
            print("  pristine snapshot taken (reset returns here)")
    rec.update(state="grabbed", artifact=dest)
    _put_rec(state, rec)
    print(f"grabbed {catalog_pill(entry)} on {ex.label} - imported as "
          f"{vm_name}, pinned to {LAB_CIDR}")
    print(f"  up: navi-labkit up {target_id}")


def _start_vm(ex, entry, rec, bridge_ok):
    vm = rec.get("vm_name")
    if not vm:
        raise LabError(f"{entry['id']} has no imported VM yet - "
                       "grab it first.")
    info = showvminfo(ex, vm)
    if info.get("VMState") == "running":
        rec["state"] = "running"
        if not rec.get("ip"):
            rec["ip"] = discover_ip(ex, vm, entry)
        return rec
    bridged = enforce_lab_network(ex, vm, bridge_ok)
    res = _vbox(ex, "startvm", vm, "--type", "headless", timeout=300)
    if not res.ok:
        raise LabError(f"startvm {vm} failed: {res.tail()}")
    rec["bridged"] = bridged
    rec["state"] = "running"
    rec["started_at"] = datetime.now().strftime("%Y-%m-%d %H:%M")
    ip = None
    for attempt in range(4):
        ip = discover_ip(ex, vm, entry)
        if ip:
            break
        if attempt < 3:
            SLEEP(5)
    rec["ip"] = ip
    return rec


def _start_docker(ex, entry, rec):
    _require_docker(ex)
    prepare_env(ex, entry)
    res = _compose(ex, entry, "up", "-d")
    if not res.ok:
        raise LabError(f"docker compose up failed for {entry['id']}: "
                       f"{res.tail()}")
    rec["state"] = "running"
    rec["ip"] = "127.0.0.1"
    rec["ports"] = entry["ports"]
    rec["started_at"] = datetime.now().strftime("%Y-%m-%d %H:%M")
    return rec


def cmd_up(opts, target_id):
    entry = _entry_or_die(target_id)
    state = load_state()
    rec = _get_rec(state, target_id)
    if not rec or rec.get("state") == "shelf":
        raise LabError(f"{target_id} is not grabbed yet - "
                       f"navi-labkit grab {target_id} first.")
    ex, note = resolve_lab(opts)
    if note:
        print(note)
    maybe_ram_warning(ex, entry)
    rec["host_label"] = ex.label
    bridge_ok = bool(opts.get("bridge_ok"))
    if entry["kind"] == "docker":
        if bridge_ok:
            print("note: --bridge-ok does not apply to Vulhub targets - "
                  "their ports stay bound to 127.0.0.1, always.")
        rec = _start_docker(ex, entry, rec)
    else:
        _require_vbox(ex)
        if bridge_ok:
            print("WARNING: --bridge-ok puts this deliberately "
                  "vulnerable box ON THE HOME LAN for this run. "
                  "Anyone on the LAN can reach it. Ctrl-C now if that "
                  "is not what you meant.")
        rec = _start_vm(ex, entry, rec, bridge_ok)
    _put_rec(state, rec)
    print(instance_pill(rec))
    if entry["kind"] == "docker":
        ports = ", ".join(str(p) for p in entry["ports"])
        print(f"  reach it at 127.0.0.1 (ports {ports}) on {ex.label}"
              " - through the DHD session or an ssh tunnel.")
    elif rec.get("ip"):
        print(f"  reach it at {rec['ip']} on the lab segment from "
              f"{ex.label}.")
    else:
        print("  IP not discovered yet - give it a minute, then: "
              f"navi-labkit status {target_id}")


def cmd_down(opts, target_id):
    entry = _entry_or_die(target_id)
    state = load_state()
    rec = _get_rec(state, target_id)
    if not rec:
        raise LabError(f"{target_id} is not grabbed - nothing to stop.")
    ex, note = resolve_lab(opts)
    if note:
        print(note)
    if entry["kind"] == "docker":
        res = _compose(ex, entry, "down")
        if not res.ok:
            raise LabError(f"docker compose down failed: {res.tail()}")
    else:
        vm = rec.get("vm_name")
        if vm:
            _vbox(ex, "controlvm", vm, "poweroff", timeout=120)
    rec.update(state="stopped", ip=None, bridged=False)
    _put_rec(state, rec)
    print(f"down: {instance_pill(rec)}")


def cmd_kill(opts, target_id):
    entry = _entry_or_die(target_id)
    state = load_state()
    rec = _get_rec(state, target_id)
    if not rec:
        raise LabError(f"{target_id} is not grabbed - nothing to kill.")
    ex, note = resolve_lab(opts)
    if note:
        print(note)
    if entry["kind"] == "docker":
        _compose(ex, entry, "down", "-v")
        ex.run(["rm", "-rf", _env_workdir(ex, entry)], timeout=120)
        rec.update(state="grabbed", ip=None, started_at=None)
        _put_rec(state, rec)
        print(f"killed {catalog_pill(entry)} - containers and volumes "
              "removed; the Vulhub clone stays on the shelf.")
        return
    vm = rec.get("vm_name")
    if vm:
        _vbox(ex, "controlvm", vm, "poweroff", timeout=120)
        res = _vbox(ex, "unregistervm", vm, "--delete", timeout=600)
        if not res.ok:
            raise LabError(f"unregistervm {vm} failed: {res.tail()}")
    rec.update(state="grabbed", ip=None, bridged=False, vm_name=None,
               started_at=None)
    _put_rec(state, rec)
    print(f"killed {catalog_pill(entry)} - VM and its disks removed; "
          "the verified artifact stays on the shelf for a fresh grab.")


def cmd_reset(opts, target_id):
    entry = _entry_or_die(target_id)
    state = load_state()
    rec = _get_rec(state, target_id)
    if not rec:
        raise LabError(f"{target_id} is not grabbed - nothing to reset.")
    ex, note = resolve_lab(opts)
    if note:
        print(note)
    if entry["kind"] == "docker":
        _compose(ex, entry, "down", "-v")
        rec.update(state="grabbed", ip=None, started_at=None)
        _put_rec(state, rec)
        print(f"reset {catalog_pill(entry)} - environment wiped; "
              f"up it again for a pristine run.")
        return
    vm = rec.get("vm_name")
    if not vm:
        raise LabError(f"{target_id} has no VM - grab it again.")
    _vbox(ex, "controlvm", vm, "poweroff", timeout=120)
    snaps = _vbox(ex, "snapshot", vm, "list", timeout=60).out
    if "labkit-pristine" in snaps:
        res = _vbox(ex, "snapshot", vm, "restore", "labkit-pristine",
                    timeout=600)
        if not res.ok:
            raise LabError(f"snapshot restore failed: {res.tail()}")
        print(f"reset {catalog_pill(entry)} - restored to the "
              "pristine snapshot taken at grab time.")
    else:
        _vbox(ex, "unregistervm", vm, "--delete", timeout=600)
        rec["vm_name"] = import_vm(ex, rec["artifact"], entry)
        adapter = ensure_lab_adapter(ex)
        _vbox(ex, "modifyvm", rec["vm_name"], "--nic1", "hostonly",
              "--hostonlyadapter1", adapter, "--cableconnected1", "on",
              timeout=120)
        print(f"reset {catalog_pill(entry)} - no snapshot existed, so "
              "the VM was re-imported from the verified artifact.")
    rec.update(state="grabbed", ip=None, bridged=False, started_at=None)
    _put_rec(state, rec)


def cmd_status(opts, target_id=None):
    cfg = load_config()
    local = detect_on(LocalExecutor())
    print("navi-labkit status")
    print(f"  this machine: docker {'yes' if local['docker'] else 'no'}"
          f" · virtualbox {'yes' if local['vbox'] else 'no'}"
          f" · ram {local['ram_gib'] or 'unknown'} GiB")
    host_name = opts.get("host") or cfg.get("lab_host_name")
    if host_name:
        print(f"  lab host {host_name}: "
              f"{'reachable over ssh' if ssh_reachable(host_name) else 'not reachable over ssh'}")
    state = load_state()
    recs = state["instances"]
    if target_id:
        entry = _entry_or_die(target_id)
        rec = recs.get(target_id)
        print()
        print(f"  {catalog_pill(entry)}")
        print(f"    id {entry['id']} - {entry['difficulty']}")
        print(f"    objective: {entry['objective']}")
        if entry["kind"] == "vm":
            print(f"    file {entry['filename']} ({entry['size_human']})"
                  f" - published MD5 {entry.get('md5') or 'none'}"
                  f" / SHA1 {entry.get('sha1') or 'not published'}")
        else:
            print(f"    image {entry['image']} - repo path "
                  f"{entry['path']}")
        if rec:
            print(f"    {instance_pill(rec)}")
            if rec.get("vm_name"):
                print(f"    vm {rec['vm_name']} - artifact "
                      f"{rec.get('artifact')}")
            if rec.get("started_at"):
                print(f"    up since {rec['started_at']}")
        else:
            print("    not grabbed yet - navi-labkit grab " + target_id)
        return
    print()
    if not recs:
        print("  nothing on the bench yet - navi-labkit shelf, "
              "then grab one.")
        return
    for target_id in sorted(recs):
        print(f"  {instance_pill(recs[target_id])}")


# --------------------------------------------------------------------------
# Case Files (#137 format) + the mini-CTF scorecard

def _slugify_case(name):
    slug = re.sub(r"[^A-Za-z0-9]+", "-", name).strip("-").lower()
    return slug or "case"


def _frontmatter(pairs, body):
    head = "".join(f"{k}: {v}\n" for k, v in pairs)
    return f"---\n{head}---\n\n{body}"


def _vault_root(opts):
    root = opts.get("vault") or os.environ.get("NAVI_VAULT_DIR")
    if root:
        return os.path.expanduser(root), None
    home_vault = os.path.join(os.path.expanduser("~"), "vault")
    if os.path.isdir(home_vault):
        return home_vault, None
    fallback = os.path.join(state_dir(), "cases-vault")
    return fallback, ("note: no Vault found (~/vault, NAVI_VAULT_DIR, "
                      "--vault) - the case was written under " +
                      fallback + " instead.")


def write_case_file(opts, name, stood_up):
    """Create a Case File in the #137 format. stood_up = list of
    (entry, rec) for targets now running. Returns the case directory."""
    vault, note = _vault_root(opts)
    if note:
        print(note)
    cases_dir = os.path.join(vault, "cases")
    os.makedirs(cases_dir, exist_ok=True)
    slug = _slugify_case(name)
    base, n = slug, 2
    while os.path.exists(os.path.join(cases_dir, slug)):
        slug = f"{base}-{n}"
        n += 1
    case_dir = os.path.join(cases_dir, slug)
    os.makedirs(os.path.join(case_dir, "findings"))
    os.makedirs(os.path.join(case_dir, "evidence"))
    now = datetime.now()
    today = now.strftime("%Y-%m-%d")
    stamp = now.strftime("%Y%m%d-%H%M%S")
    filed = now.strftime("%Y-%m-%d %H:%M")
    case_md = _frontmatter(
        [("title", name), ("client", "Home lab"),
         ("scope", f"navi-labkit mini-CTF - isolated lab segment "
                   f"{LAB_CIDR}"),
         ("status", "open"), ("opened", today)],
        f"# {name}\n\nThe case manifest. Findings live in `findings/`, "
        "evidence in `evidence/`, the story in `timeline.md`.\n")
    with open(os.path.join(case_dir, "case.md"), "w",
              encoding="utf-8") as fh:
        fh.write(case_md)
    timeline = (f"# Timeline — {name}\n\n## {today} — Case opened\n\n"
                "The case was opened.\n")
    entry_block = (
        f"## {filed} — Mini-CTF stood up\n\n"
        f"navi-labkit stood up {len(stood_up)} target(s) on the "
        f"isolated lab segment: "
        + ", ".join(e["name"] for e, _ in stood_up)
        + ". Scorecard in `scorecard.md`, one finding per target.\n\n")
    timeline = timeline.replace(f"# Timeline — {name}\n\n",
                                f"# Timeline — {name}\n\n" + entry_block, 1)
    with open(os.path.join(case_dir, "timeline.md"), "w",
              encoding="utf-8") as fh:
        fh.write(timeline)
    rows = []
    for entry, rec in stood_up:
        title = f"{entry['name']} - objective"
        body = (f"# {title}\n\nObjective: {entry['objective']}\n\n"
                f"{instance_pill(rec)}\n\nFlag: __________\n\nNotes:\n")
        finding = _frontmatter(
            [("title", title), ("severity", "info"),
             ("internal", "yes"), ("filed", filed)], body)
        fname = f"{stamp}-{_slugify_case(entry['name'])}.md"
        with open(os.path.join(case_dir, "findings", fname), "w",
                  encoding="utf-8") as fh:
            fh.write(finding)
        rows.append(
            f"| {entry['name']} | {SOURCE_LABEL[entry['source']]} | "
            f"{rec.get('ip') or 'pending'} | {entry['objective']} | "
            "| 100 |")
    scorecard = (f"# Scorecard — {name}\n\n"
                 "| Target | Source | IP | Objective | Flag | Points |\n"
                 "| --- | --- | --- | --- | --- | --- |\n"
                 + "\n".join(rows)
                 + f"\n\nTotal available: {100 * len(stood_up)} points. "
                 "Fill the Flag column as flags land (each target's "
                 "finding note has a flag line too).\n")
    with open(os.path.join(case_dir, "scorecard.md"), "w",
              encoding="utf-8") as fh:
        fh.write(scorecard)
    return case_dir


def cmd_ctf(opts):
    raw = opts.get("targets") or ""
    ids = [t.strip() for t in raw.split(",") if t.strip()]
    if not ids:
        raise LabError("ctf needs targets: navi-labkit ctf \"Lab Night\""
                       " --targets vulnhub/dc-1,"
                       "vulhub/drupal-cve-2018-7600")
    name = opts.get("name") or (
        "Mini-CTF " + datetime.now().strftime("%Y-%m-%d"))
    state = load_state()
    plan = []
    missing = []
    for target_id in ids:
        entry = _entry_or_die(target_id)
        rec = _get_rec(state, target_id)
        if not rec or rec.get("state") == "shelf":
            missing.append(target_id)
        else:
            plan.append((entry, rec))
    if missing:
        raise LabError(
            "not grabbed yet: " + ", ".join(missing) + " - grab them "
            "first (ctf never downloads multi-GB boxes silently).")
    ex, note = resolve_lab(opts)
    if note:
        print(note)
    stood_up = []
    for entry, rec in plan:
        rec["host_label"] = ex.label
        if rec.get("state") != "running":
            if entry["kind"] == "docker":
                rec = _start_docker(ex, entry, rec)
            else:
                _require_vbox(ex)
                rec = _start_vm(ex, entry, rec, bridge_ok=False)
            _put_rec(state, rec)
        stood_up.append((entry, rec))
        print(f"  up: {instance_pill(rec)}")
    case_dir = write_case_file(opts, name, stood_up)
    print(f"mini-CTF '{name}' is live - scorecard + findings in the "
          f"Case File: {case_dir}")


# --------------------------------------------------------------------------
# CLI surface

HELP = """navi-labkit - home-lab targets (VulnHub VMs + Vulhub Docker), run safely

  shelf                     the bundled starter catalog, with sources
  grab <target> [--file P]  download (or clone), VERIFY the checksum, import
  up <target> [--bridge-ok] start it on the isolated lab segment
  down <target>             stop it (VM state / containers kept)
  kill <target>             stop + remove the VM/containers and their disks
  reset <target>            back to pristine (snapshot or fresh import)
  status [<target>]         hosts, instances, IPs - the provenance pills
  ctf <name> --targets a,b  stand targets up + write a Case File scorecard
  hosts                     what each machine can actually run

  --host <name|local>       run targets on this lab host (ssh) or locally
                            (default: NeoArcadia when it answers, else local)

Lab law: VulnHub VMs live on host-only 192.168.56.0/24 and Vulhub ports
bind 127.0.0.1. Nothing touches the home LAN without --bridge-ok on that
one box. Downloads are checksum-verified before import - a mismatch
refuses, loudly. State and config: ~/navi-labkit/ (NAVI_LABKIT_HOME)."""


def _parse_opts(tokens):
    opts = {"host": None, "file": None, "targets": None, "name": None,
            "vault": None, "bridge_ok": False}
    positional = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok == "--bridge-ok":
            opts["bridge_ok"] = True
        elif tok in ("--host", "--file", "--targets", "--name",
                     "--vault") and i + 1 < len(tokens):
            opts[tok.lstrip("-").replace("-", "_")] = tokens[i + 1]
            i += 1
        elif tok.startswith("--"):
            raise LabError(f"unknown flag {tok} - see: navi-labkit help")
        else:
            positional.append(tok)
        i += 1
    return opts, positional


def run_command(argv):
    """Entry point used by root.py. Returns a process-style exit code."""
    try:
        return _run(list(argv))
    except LabError as exc:
        print(f"error: {exc}")
        return 1


def _run(argv):
    if not argv or argv[0] in ("help", "--help", "-h"):
        print(HELP)
        return 0
    if argv[0] == "--test":
        return run_tests()
    cmd, rest = argv[0], argv[1:]
    opts, positional = _parse_opts(rest)
    if cmd == "shelf":
        cmd_shelf(opts)
    elif cmd == "hosts":
        cmd_hosts(opts)
    elif cmd == "status":
        cmd_status(opts, positional[0] if positional else None)
    elif cmd == "ctf":
        if positional:
            opts["name"] = " ".join(positional)
        cmd_ctf(opts)
    elif cmd in ("grab", "up", "down", "kill", "reset"):
        if not positional:
            raise LabError(f"{cmd} needs a target id - navi-labkit shelf")
        fn = {"grab": cmd_grab, "up": cmd_up, "down": cmd_down,
              "kill": cmd_kill, "reset": cmd_reset}[cmd]
        fn(opts, positional[0])
    else:
        print(HELP)
        raise LabError(f"unknown command {cmd!r}")
    return 0


# --------------------------------------------------------------------------
# Self-test: the whole world is stubbed through FakeExecutor.
# Proves command logic, checksum refusal, the lab-network law, compose
# sanitizing, pill rendering, and the Case File writer - fully offline.

def run_tests():
    global SLEEP
    checks = []

    def check(name, cond):
        checks.append((name, bool(cond)))
        print(f"  [{'ok' if cond else 'FAIL'}] {name}")

    def expect_error(name, fn, needle):
        try:
            fn()
        except LabError as exc:
            check(name, needle.lower() in str(exc).lower())
            return
        check(name + " (no error raised)", False)

    print("navi-labkit self-test (hypervisor / docker / ssh stubbed)")

    import tempfile
    tmp = tempfile.mkdtemp(prefix="labkit-test-")
    old_env = os.environ.get("NAVI_LABKIT_HOME")
    os.environ["NAVI_LABKIT_HOME"] = tmp
    old_sleep = SLEEP
    SLEEP = lambda _s: None

    payload = b"LABKIT-TEST-OVA" * 64
    good_md5 = hashlib.md5(payload).hexdigest()
    good_sha1 = hashlib.sha1(payload).hexdigest()

    world = _FakeWorld(payload)
    ex = FakeExecutor(world.handle, label="fakehost")
    global EXECUTOR_FACTORY
    old_factory = EXECUTOR_FACTORY
    EXECUTOR_FACTORY = lambda opts: ex

    test_vm = {"id": "vulnhub/test-box", "source": "vulnhub",
               "kind": "vm", "name": "Test Box", "difficulty": "Easy",
               "filename": "testbox.ova", "size_human": "1 KB",
               "size_bytes": len(payload), "md5": good_md5,
               "sha1": good_sha1, "mirror": "https://example.invalid/t",
               "entry": "", "format": "OVA", "os": "Linux",
               "archive": None, "static_ip": None,
               "objective": "Root it.", "network_note": "",
               "notes": "self-test fixture"}
    bad_vm = dict(test_vm, id="vulnhub/bad-box", name="Bad Box",
                  filename="badbox.ova", md5="0" * 32, sha1="0" * 40)
    test_env = {"id": "vulhub/test-env", "source": "vulhub",
                "kind": "docker", "name": "Test Env",
                "difficulty": "Easy", "path": "test/env",
                "image": "vulhub/test:1", "ports": [8080],
                "repo": VULHUB_REPO_URL, "cve": "TEST",
                "objective": "Shell it.", "notes": "self-test fixture"}
    TARGETS.extend([test_vm, bad_vm, test_env])
    opts = {"host": None, "file": None, "targets": None, "name": None,
            "vault": os.path.join(tmp, "vault"), "bridge_ok": False}
    try:
        # pill rendering
        pill = instance_pill({"source": "vulnhub", "name": "X",
                              "host_label": "h", "ip": "192.168.56.101",
                              "state": "running", "bridged": False})
        check("pill carries source/host/ip/state",
              pill == "[VulnHub] X · host h · ip 192.168.56.101 · running")
        check("catalog pill shows the source",
              catalog_pill(test_vm).startswith("[VulnHub] "))

        # shelf renders the real catalog
        buf = io.StringIO()
        with redirect_stdout(buf):
            cmd_shelf(opts)
        out = buf.getvalue()
        check("shelf lists DC-1 with its source",
              "[VulnHub] DC-1" in out and LAB_CIDR in out)

        # grab: download + checksum verify + import + network pin
        buf = io.StringIO()
        with redirect_stdout(buf):
            cmd_grab(opts, "vulnhub/test-box")
        out = buf.getvalue()
        rec = load_state()["instances"]["vulnhub/test-box"]
        check("grab verifies checksums", "checksum verified" in out)
        check("grab records the instance as grabbed",
              rec["state"] == "grabbed")
        check("grab pins a bridged-shipping box to host-only",
              world.vms["labkit-test-box"]["nic1"] == "hostonly")
        check("grab takes the pristine snapshot",
              world.snapped.get("labkit-test-box", False))

        # checksum refusal: nothing imported, file deleted
        expect_error("checksum mismatch refuses, loudly",
                     lambda: cmd_grab(opts, "vulnhub/bad-box"),
                     "checksum mismatch")
        dest = ("/fakehome/navi-labkit/store/vulnhub/bad-box/badbox.ova")
        check("mismatched file is deleted, never imported",
              dest not in world.fs
              and "labkit-bad-box" not in world.vms)

        # the lab-network law: bridged config + no opt-in = refusal
        world.vms["labkit-test-box"]["nic1"] = "bridged"
        expect_error("bridged config without --bridge-ok is refused",
                     lambda: cmd_up(opts, "vulnhub/test-box"), "refused")
        check("refused VM was never started",
              world.vms["labkit-test-box"]["VMState"] != "running")

        # explicit opt-in: bridges, warns, and the pill says so
        buf = io.StringIO()
        with redirect_stdout(buf):
            cmd_up(dict(opts, bridge_ok=True), "vulnhub/test-box")
        out = buf.getvalue()
        rec = load_state()["instances"]["vulnhub/test-box"]
        check("--bridge-ok warns before bridging", "WARNING" in out)
        check("bridged pill carries the opt-in marker",
              "BRIDGED (opted in)" in instance_pill(rec))
        check("bridged up still discovers the lab IP",
              rec["ip"] == "192.168.56.101")

        # back to lawful: down, re-pin by hand, up on the segment
        cmd_down(opts, "vulnhub/test-box")
        world.vms["labkit-test-box"]["nic1"] = "hostonly"
        world.vms["labkit-test-box"]["hostonlyadapter1"] = "vboxnet0"
        buf = io.StringIO()
        with redirect_stdout(buf):
            cmd_up(opts, "vulnhub/test-box")
        rec = load_state()["instances"]["vulnhub/test-box"]
        check("normal up runs on the lab segment",
              rec["state"] == "running" and not rec["bridged"]
              and rec["ip"] == "192.168.56.101")

        # compose sanitizer: the Docker half of the law
        good, ports = sanitize_compose(
            'services:\n  web:\n    ports:\n      - "8080:80"\n',
            test_env)
        check("compose ports rebind to 127.0.0.1",
              '"127.0.0.1:8080:80"' in good and ports == [8080])
        expect_error("compose publishing on a LAN address is refused",
                     lambda: sanitize_compose(
                         'services:\n  web:\n    ports:\n'
                         '      - "192.168.1.50:8080:80"\n', test_env),
                     "refused")
        expect_error("long-syntax port mappings are refused",
                     lambda: sanitize_compose(
                         "services:\n  web:\n    ports:\n"
                         "      - target: 80\n        published: 8080\n",
                         test_env),
                     "refused")
        expect_error("host networking is refused",
                     lambda: sanitize_compose(
                         "services:\n  web:\n    network_mode: host\n",
                         test_env),
                     "refused")

        # vulhub flow: grab prepares a sanitized compose; up runs it
        buf = io.StringIO()
        with redirect_stdout(buf):
            cmd_grab(opts, "vulhub/test-env")
            cmd_up(opts, "vulhub/test-env")
        gen = ("/fakehome/navi-labkit/store/envs/test-env/"
               "docker-compose.labkit.yml")
        check("vulhub grab writes the sanitized compose file",
              "127.0.0.1:8080:80" in world.fs.get(gen, b"").decode())
        rec = load_state()["instances"]["vulhub/test-env"]
        check("vulhub up records loopback + running",
              rec["state"] == "running" and rec["ip"] == "127.0.0.1")

        # ctf: Case File in the #137 format with a scorecard
        cmd_ctf(dict(opts, targets="vulnhub/test-box,vulhub/test-env",
                     name="Test Night"))
        case_dir = os.path.join(tmp, "vault", "cases", "test-night")
        case_md = open(os.path.join(case_dir, "case.md"),
                       encoding="utf-8").read()
        keys = [ln.split(":")[0] for ln in case_md.splitlines()
                if ln and not ln.startswith(("---", "#"))]
        check("case.md frontmatter matches the #137 pair order",
              keys[:5] == ["title", "client", "scope", "status",
                           "opened"])
        findings = os.listdir(os.path.join(case_dir, "findings"))
        scorecard = open(os.path.join(case_dir, "scorecard.md"),
                         encoding="utf-8").read()
        timeline = open(os.path.join(case_dir, "timeline.md"),
                        encoding="utf-8").read()
        check("one finding per target + scorecard + timeline entry",
              len(findings) == 2 and "Test Box" in scorecard
              and "Mini-CTF stood up" in timeline)

        # reset via snapshot, kill back to the shelf
        cmd_reset(opts, "vulnhub/test-box")
        rec = load_state()["instances"]["vulnhub/test-box"]
        check("reset restores the pristine snapshot",
              rec["state"] == "grabbed")
        cmd_kill(opts, "vulnhub/test-box")
        rec = load_state()["instances"]["vulnhub/test-box"]
        check("kill removes the VM, keeps the artifact on the shelf",
              rec["state"] == "grabbed" and rec["vm_name"] is None
              and "labkit-test-box" not in world.vms)
    finally:
        TARGETS[:] = [t for t in TARGETS
                      if t["id"] not in ("vulnhub/test-box",
                                         "vulnhub/bad-box",
                                         "vulhub/test-env")]
        EXECUTOR_FACTORY = old_factory
        SLEEP = old_sleep
        if old_env is None:
            os.environ.pop("NAVI_LABKIT_HOME", None)
        else:
            os.environ["NAVI_LABKIT_HOME"] = old_env

    failed = [n for n, ok in checks if not ok]
    print(f"self-test: {len(checks) - len(failed)}/{len(checks)} "
          "checks passed")
    if failed:
        print("failed: " + "; ".join(failed))
        return 1
    return 0


class _FakeWorld:
    """The stubbed lab: a VirtualBox host + filesystem + docker host."""

    def __init__(self, payload):
        self.payload = payload
        self.fs = {}          # path -> bytes
        self.dirs = set()
        self.vms = {}         # name -> info dict
        self.snapped = {}
        repo = "/fakehome/navi-labkit/store/vulhub-repo"
        self.dirs.add(repo + "/.git")
        self.fs[repo + "/test/env/docker-compose.yml"] = (
            b'services:\n  web:\n    image: vulhub/test:1\n'
            b'    ports:\n      - "8080:80"\n')

    # -- helpers ------------------------------------------------------
    def _vm_info_text(self, name):
        info = self.vms[name]
        lines = [f'{k}="{v}"' for k, v in info.items()]
        return "\n".join(lines) + "\n"

    # -- the handler --------------------------------------------------
    def handle(self, argv, cwd, stdin):
        cmd = argv[0]
        if cmd == "VBoxManage":
            return self._vbox(argv[1:])
        if cmd == "curl":
            dest = argv[argv.index("-o") + 1]
            self.fs[dest] = self.payload
            return (0, "", "")
        if cmd in ("md5sum", "sha1sum"):
            path = argv[1]
            if path not in self.fs:
                return (1, "", "no such file")
            digest = hashlib.new(cmd[:-3], self.fs[path]).hexdigest()
            return (0, f"{digest}  {path}\n", "")
        if cmd == "mkdir":
            self.dirs.add(argv[-1])
            return (0, "", "")
        if cmd == "test":
            flag, path = argv[1], argv[2]
            if flag == "-f":
                return (0 if path in self.fs else 1, "", "")
            return (0 if path in self.dirs else 1, "", "")
        if cmd == "mv":
            self.fs[argv[2]] = self.fs.pop(argv[1], b"")
            return (0, "", "")
        if cmd == "rm":
            target = argv[-1]
            self.fs.pop(target, None)
            for key in [k for k in self.fs if k.startswith(target)]:
                del self.fs[key]
            self.dirs.discard(target)
            return (0, "", "")
        if cmd == "unzip":
            out_dir = argv[argv.index("-d") + 1]
            self.fs[out_dir + "/inner.ova"] = b"ova"
            return (0, "", "")
        if cmd == "ls":
            prefix = argv[1].rstrip("/") + "/"
            names = sorted({k[len(prefix):].split("/")[0]
                            for k in self.fs if k.startswith(prefix)})
            return (0, "\n".join(names) + "\n", "")
        if cmd == "cat":
            data = self.fs.get(argv[1])
            return (0, data.decode(), "") if data is not None else \
                (1, "", "no such file")
        if cmd == "sh":
            script = argv[2]
            if "command -v curl" in script:
                return (0, "/usr/bin/curl\n", "")
            if script.startswith("cat > "):
                path = script[len("cat > "):].strip().strip("'")
                self.fs[path] = (stdin or "").encode()
                return (0, "", "")
            return (0, "", "")
        if cmd == "git":
            return (0, "git version 2.43.0\n", "")
        if cmd == "docker":
            if argv[1] == "--version":
                return (0, "Docker version 27.0.0\n", "")
            if argv[1:3] == ["compose", "version"]:
                return (0, "Docker Compose version v2.29.0\n", "")
            return (0, "", "")
        if cmd == "ip":
            return (0, "192.168.56.101 dev vboxnet0 lladdr "
                       "08:00:27:0d:12:34 REACHABLE\n", "")
        return (0, "", "")

    def _vbox(self, args):
        if args[0] == "--version":
            return (0, "7.0.14\n", "")
        if args[0] == "list":
            what = args[1]
            if what == "hostonlyifs":
                return (0, "Name:            vboxnet0\n"
                           "IPAddress:       192.168.56.1\n"
                           "NetworkMask:     255.255.255.0\n", "")
            if what == "bridgedifs":
                return (0, "Name:            eth-test0\n"
                           "IPAddress:       192.168.1.10\n", "")
            if what == "vms":
                return (0, "".join(f'"{n}" {{uuid}}\n' for n in self.vms),
                        "")
            if what == "dhcpservers":
                return (0, "NetworkName:    "
                           "HostInterfaceNetworking-vboxnet0\n"
                           "Enabled:        Yes\n", "")
        if args[0] == "import":
            name = args[args.index("--vmname") + 1]
            # the fixture box SHIPS bridged, like DC-1 does
            self.vms[name] = {"VMState": "poweroff", "nic1": "bridged",
                              "bridgeadapter1": "eth-test0",
                              "macaddress1": "0800270D1234"}
            return (0, "Successfully imported\n", "")
        if args[0] == "showvminfo":
            return (0, self._vm_info_text(args[1]), "")
        if args[0] == "modifyvm":
            info = self.vms[args[1]]
            for key, flag in (("nic1", "--nic1"),
                              ("hostonlyadapter1", "--hostonlyadapter1"),
                              ("bridgeadapter1", "--bridgeadapter1")):
                if flag in args:
                    info[key] = args[args.index(flag) + 1]
            return (0, "", "")
        if args[0] == "snapshot":
            name, action = args[1], args[2]
            if action == "list":
                return (0, "labkit-pristine\n" if self.snapped.get(name)
                        else "This machine does not have any snapshots\n",
                        "")
            if action == "take":
                self.snapped[name] = True
            return (0, "", "")
        if args[0] == "startvm":
            self.vms[args[1]]["VMState"] = "running"
            return (0, "VM started\n", "")
        if args[0] == "controlvm":
            self.vms[args[1]]["VMState"] = "poweroff"
            return (0, "", "")
        if args[0] == "unregistervm":
            self.vms.pop(args[1], None)
            return (0, "", "")
        if args[0] == "guestproperty":
            return (0, "Value: 192.168.56.101\n", "")
        if args[0] in ("hostonlyif", "dhcpserver"):
            return (0, "", "")
        return (0, "", "")
