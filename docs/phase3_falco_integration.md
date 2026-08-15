# Phase 3 — Falco + eBPF (Rule-Based Layer)

## What this phase delivers

- `runtime-monitor/falco_integration.py` — parses Falco's JSON alert output,
  normalizes it into ContainerGuard AI's internal schema (shape #1, see
  `docs/interfaces.md`), and exposes both a live-tailing generator
  (`stream_falco_alerts`) and a finite batch reader
  (`read_falco_alerts_from_file`) for the rest of the pipeline to consume.
- `runtime-monitor/ebpf_collector.py` — a thin, documented facade over
  `falco_integration.stream_raw_events`. See "Scope decision" below.
- `tests/test_falco_integration.py` — 20 unit tests, all mocked/fixture-based
  (no live Falco, Docker, or network required).
- `runtime-monitor/falco_output_config_snippet.yaml` — the exact Falco
  config keys this project needs, to merge into your real `falco.yaml`.

## What's original vs. off-the-shelf

- **Off-the-shelf:** Falco itself (the eBPF probe, rule engine, and default
  ruleset) and the modern eBPF driver it uses to read kernel events.
- **Original:** the JSON parsing/normalization logic, defensive error
  handling (malformed lines, missing fields, host-vs-container filtering,
  priority-casing normalization), the live-tail-vs-batch-read split (the
  batch reader doubles as what Phase 6's backtester will need), and the
  documented scope decision not to duplicate a second eBPF collector.

## Scope decision: no separate raw eBPF collector

`ebpf_collector.py` does not implement its own eBPF program. It's a thin
facade over `falco_integration.stream_falco_alerts`, because Falco's own
modern eBPF probe already surfaces everything this project needs, and
building a second one would mean loading a second kernel-level probe for no
additional detection capability. The full justification is in
`ebpf_collector.py`'s module docstring — read that if you need the exact
wording for your report or a viva answer. This is flagged explicitly
because it's a deliberate scope call, not an oversight, and it's the kind
of thing an evaluator might ask about.

If you disagree with this call and want a real, separate eBPF collector
(e.g. via `bcc` or `libbpf` directly), that's a legitimate alternative —
it would add real schedule risk to an already time-risky phase, so weigh
that before taking it on.

---

## What you need to do on your Linux VM

I can't install or run Falco myself — my sandbox has no network access and
isn't your target Linux environment. Everything below is what you run
yourself. All commands and config keys here were checked against Falco's
current documentation before writing this, not recalled from memory.

### 1. Prerequisites

```bash
uname -r
```
Modern eBPF (the driver you want — no kernel module, no compilation) needs
kernel **5.8+**. Check `ldd --version` too — Falco's packages need **GLIBC
2.28+**. Use a native Linux box or cloud VM (Ubuntu 22.04/24.04), not WSL2,
per the existing project guide — eBPF driver loading is smoother there.

### 2. Install Falco (DEB, non-interactive, modern eBPF)

```bash
# Trust the Falco GPG key
curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | \
  sudo gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg

# Add the apt repository
echo "deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main" | \
  sudo tee -a /etc/apt/sources.list.d/falcosecurity.list

sudo apt-get update -y

# Non-interactive install, modern eBPF driver, no auto rule-updates
sudo FALCO_FRONTEND=noninteractive FALCO_DRIVER_CHOICE=modern_ebpf FALCOCTL_ENABLED=no \
  apt-get install -y falco
```

`FALCO_DRIVER_CHOICE=modern_ebpf` skips the interactive dialog and selects
the modern eBPF driver directly — it's bundled into the Falco binary, so
there's no kernel module to build or compile.

### 3. Confirm it's running

```bash
sudo systemctl status falco-modern-bpf
```
(The unit is named `falco-modern-bpf.service` specifically when using the
modern eBPF driver — if that name doesn't match what you see, run
`systemctl list-units | grep falco` to find the actual unit name on your
install.)

### 4. Configure JSON + file output

Edit `/etc/falco/falco.yaml` (find and change these keys — most already
exist with different defaults, don't just append duplicates) to match
`runtime-monitor/falco_output_config_snippet.yaml`:

```yaml
json_output: true
json_include_output_property: true
json_include_tags_property: true
time_format_iso_8601: true

file_output:
  enabled: true
  keep_alive: false
  filename: /var/log/falco/alerts.json

stdout_output:
  enabled: true
```

```bash
sudo mkdir -p /var/log/falco
sudo systemctl restart falco-modern-bpf
sudo systemctl status falco-modern-bpf   # confirm it restarted clean
```

### 5. Trigger a test alert — your "hello world"

```bash
docker run -d --name test-container nginx:1.25
docker exec -it test-container sh
# you're now inside the container's shell — just exit immediately
exit
```

Opening a shell inside a running container matches Falco's built-in
**"Terminal shell in container"** rule (`WARNING` priority) and should fire
within seconds.

### 6. Confirm the alert landed in both places

```bash
# Falco's own service log
sudo journalctl -u falco-modern-bpf -f

# the JSON file this project's code will actually read
tail -f /var/log/falco/alerts.json
```
You should see one JSON line per alert, containing `"rule": "Terminal shell
in container"` and an `output_fields` object with `"container.id"` set to
your test container's real ID.

### 7. Run this project's parser against your real alert

This is the step that proves the code, not just Falco, actually works —
copy `runtime-monitor/` and `tests/` into your repo first (see
"Integrating into your repo" below), then:

```bash
cd containerguard-ai/runtime-monitor
python3 falco_integration.py /var/log/falco/alerts.json --mode batch
```
You should see your real alert printed back as a normalized shape-#1 JSON
line, with the real `container_id` Docker assigned your test container.
Then try live-tailing mode while triggering a second alert in another
terminal:
```bash
python3 falco_integration.py /var/log/falco/alerts.json --mode tail
# in a second terminal: docker exec -it test-container sh, then exit
```
The new alert should print within ~1 second (the default poll interval).

---

## Automated tests — what's covered, what isn't, and why

`tests/test_falco_integration.py` (20 tests, run with
`python3 -m unittest tests.test_falco_integration -v` or `pytest tests/
-v`) covers, using fixture Falco JSON (no live process needed):

- Parsing a valid alert into the correct normalized shape
- Priority-casing normalization (`"Warning"` → `"WARNING"`,
  `"Informational"` → `"INFO"`)
- Host-level events (`container.id: "host"`, case-insensitive) correctly
  resolving to `container_id: null` and being filterable
- Malformed JSON, empty lines, and missing required fields all raising
  `FalcoParseError` cleanly rather than crashing
- A missing `output_fields` key not crashing the parser
- `read_falco_alerts_from_file()` against a real (but static, fixture)
  file on disk — genuine file I/O, deterministic
- `stream_falco_alerts(from_start=True)` bounded via `itertools.islice` —
  also genuine file I/O, still deterministic since it only reads
  pre-existing content
- `ebpf_collector.stream_raw_events()` actually delegating to
  `falco_integration`, not silently diverging

**Not covered by automated tests, deliberately:** `stream_falco_alerts()`'s
live-tailing behavior — blocking and waking up when Falco appends a
genuinely new line in real time. That's a timing/I-O concern against a real
process, which is exactly what step 7 above validates manually. A threaded
test simulating this would be flaky in CI for little benefit; the manual
validation is the real proof this works.

---

## Integrating into your repo

These files are additive — nothing here touches `image-scanner/` or
`policy-checker/` from Phases 1–2. From the folder you unzip this into:

```bash
cp -r runtime-monitor ~/containerguard-ai/
cp tests/test_falco_integration.py ~/containerguard-ai/tests/
cp -r docs/* ~/containerguard-ai/docs/          # merges interfaces.md + this file in
cd ~/containerguard-ai
python3 -m unittest tests.test_falco_integration -v   # confirm 20/20 pass in your real repo too
```

No `requirements.txt` changes needed — this phase uses only the Python
standard library (`json`, `logging`, `time`, `pathlib`, `dataclasses`,
`typing`). No Docker SDK, no new pip packages.

---

## Known limitations at this stage

- `stream_falco_alerts()` uses simple polling (`readline` + `sleep`), not
  filesystem event notification (e.g. `inotify`) — fine at this project's
  scale, but worth knowing if alert latency ever needs to be sub-second at
  higher event volumes.
- No log rotation handling — if `/var/log/falco/alerts.json` gets rotated
  (e.g. by `logrotate`) while `stream_falco_alerts()` holds an open file
  handle, it won't follow the rotation. Not a concern for a demo-length
  capstone run; would need `filename` re-open/inode-change detection for a
  production deployment.
- Container attribution depends on Falco's bundled container plugin, which
  is included by default in the DEB/RPM host install used here. If you ever
  switch install methods (building from source, a minimal container image),
  confirm the container plugin is loaded — otherwise `container.id` /
  `container.name` fields won't populate at all.
- Not yet wired into Phase 4 — `ebpf_collector.stream_raw_events()` exists
  specifically so Phase 4's feature extractor has a stable import target,
  but Phase 4 doesn't exist yet.
