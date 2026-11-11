# navi-labkit

A home-lab target manager for [Apex](https://github.com/AlexKollar/Apex).
It downloads, verifies, runs, and retires **deliberately vulnerable
practice targets** — VulnHub VMs and Vulhub Docker environments — so a
lab night is three commands instead of an afternoon of downloads,
imports, and "which network is that thing on again?"

```
navi-labkit grab vulnhub/dc-1
navi-labkit up vulnhub/dc-1
navi-labkit ctf "Friday Night" --targets vulnhub/dc-1,vulhub/drupal-cve-2018-7600
```

Every target carries its **provenance pill** wherever it appears:
`[VulnHub] DC-1 · host neoarcadia · ip 192.168.56.101 · running` —
source, host, IP, state, at a glance in any transcript.

## The lab law (enforced in code, not just documented)

These boxes are *supposed* to be broken into. They never get the chance
to be reached by — or to reach — anything else:

- **VulnHub VMs run on an isolated host-only VirtualBox segment,
  `192.168.56.0/24`** (DHCP included), created and verified by the chip
  before anything boots. A VM found configured for bridged networking
  is **refused** unless that one box is explicitly opted in for that
  one start: `up <target> --bridge-ok` (with a loud warning, and the
  pill carries a `BRIDGED (opted in)` marker while it lasts). Boxes
  that *ship* bridged — DC-1 does — are re-pinned to the segment at
  grab time, before first boot.
- **Vulhub ports are rebound to `127.0.0.1`** in a generated compose
  file before anything starts. A compose file that publishes on a LAN
  address, uses long-syntax port mappings the chip cannot verify, or
  asks for host networking is **refused, loudly**.
- **Downloads are checksum-verified before import** against the
  checksums published with the catalog entry (MD5 and/or SHA1, exactly
  as published). A mismatch deletes the file and refuses. No
  exceptions, no "import anyway" flag.
- Catalog data is data. Nothing in the catalog is ever executed.

## Commands

| Command | What it does |
| --- | --- |
| `shelf` | The bundled starter catalog, with sources |
| `grab <target> [--file P]` | Download (or clone, for Vulhub), verify, import, pin to the lab segment, snapshot pristine |
| `up <target> [--bridge-ok]` | Start it; print its pill with the discovered IP |
| `down <target>` | Stop it; VM state / shelf artifacts kept |
| `kill <target>` | Stop + remove the VM/containers and their disks; the verified artifact stays on the shelf |
| `reset <target>` | Back to pristine (snapshot restore, or fresh import) |
| `status [<target>]` | Host capabilities + every instance's pill |
| `ctf <name> --targets a,b` | Stand targets up and write a Case File scorecard |
| `hosts` | What each machine can actually run (detected, never assumed) |

## Hosts: where targets live

VM targets default to the **lab host — NeoArcadia — over SSH**, using
your existing ssh config, keys, and agent (the chip stores no
credentials and accepts no passwords). This machine is the fallback,
with a RAM warning when it's small. `--host <name|local>` or a
`labkit.json` in the state dir (`~/navi-labkit/`, or
`$NAVI_LABKIT_HOME`) pins the choice:

```json
{ "lab_host": "neoarcadia" }
```

Vulhub environments run via `docker compose` wherever Docker lives.
Detection (`hosts`, `status`) reports what is actually there — Docker,
Compose, VirtualBox, git, curl, RAM — and every command refuses
plainly when its tool is missing instead of faking it.

**DHD-first:** LabKit is a chip, so everything above works from Apex
chat — at the desk, or remotely through DHD into the home install.
The lab itself runs on NeoArcadia; interactive work against a target
(reverse shells, msfconsole) belongs on the SSH bench, which is also
where the chip leaves you: every `up` prints exactly where the target
can be reached.

## The starter shelf

Bundled, curated, and verified on 2026-11-11: VulnHub file data from
each machine's vulnhub.com entry page, every mirror confirmed live
with a size matching the published size; Vulhub paths, images, and
ports read from the live `vulhub/vulhub` repo.

- **VulnHub:** DC-1 · Basic Pentesting: 1 · Mr-Robot: 1 · Phineas: 1 ·
  Depth: 1 (beginner → intermediate)
- **Vulhub:** Drupal CVE-2018-7600 · Struts2 S2-045 · ThinkPHP 5.0.23
  RCE · WebLogic CVE-2017-10271 · ActiveMQ CVE-2015-5254 · Solr
  CVE-2019-17558

Known data gap, on the record: DC-1's entry did not expose a SHA1 in
any rendering fetched on 2026-11-11, so its verification rides on the
published MD5 (quoted from the entry's info block; mirror and size
confirmed on the entry itself and live). Metasploitable joins the
shelf in a later build — the pill already knows the source.

## Mini-CTFs

`ctf` stands the named targets up (they must be grabbed first — it
never downloads multi-GB boxes silently) and writes a **Case File**
in the Apex Case Files format (`case.md`, `findings/`, `timeline.md`)
plus a `scorecard.md`: one finding per target with its objective, its
pill, and a blank flag line. Cases land in the Vault (`~/vault`,
`$NAVI_VAULT_DIR`, or `--vault`) under `cases/`.

## Development

Standard library only — no `pip install`, ever. Host tools are driven,
never installed by the chip: VirtualBox, Docker + Compose v2, git,
curl/wget, ssh.

```
python3 root.py --test   # offline self-test: stubbed hypervisor/docker/ssh
```

The self-test proves the command logic, the checksum refusal, the
lab-network law (a bridged config without the opt-in is refused by the
code path), the compose sanitizer, the pill rendering, and the Case
File writer — 25 checks, no network, no hypervisor.
