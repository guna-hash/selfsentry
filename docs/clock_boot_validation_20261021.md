# Falco boot-clock mitigation — 21 October 2026

Falco previously opened its engine at 13.33 seconds after boot, before
initial NTP synchronization at 41.81 seconds. A native probe recorded
18 events with 19800.352 seconds of skew. Invalid evidence is retained
at state/evaluation/clock-followup-abulylao.

The installed systemd drop-in orders Falco after time-sync.target and
systemd-time-wait-sync.service. After reboot, the wait service completed
at 40.310723 seconds and Falco started at 40.357363 seconds.

The post-reboot native probe passed: 20 events, zero observed skew.
Evidence: state/evaluation/clock-after-reboot-cq8mkx_x.
This verifies the mitigation for one reboot; suspend/resume and later
clock corrections remain unverified.

Evaluation preflights now bind to boot identity and realtime/monotonic
samples, rejecting missing lifecycle evidence and clock discontinuities.
This protects evaluation validity; it does not repair Falco timestamps.

VM release checks passed: 538 Python tests plus 7 subtests, lint,
150 frontend tests and production build.
Evidence: state/evaluation/final-checks-20261021T092120Z.

Sample-mode missing risk guidance no longer suggests a backend retry.

Install on another system:
  sudo mkdir -p /etc/systemd/system/falco-modern-bpf.service.d
  sudo cp ops/systemd/falco-clock-ordering.conf \
    /etc/systemd/system/falco-modern-bpf.service.d/clock-ordering.conf
  sudo systemctl daemon-reload

If synchronization is unavailable, Falco startup may wait. Validate
ordering and native timestamps after reboot. Automatic study actions
remain disabled; no unattended-use or permanent clock-fix claim follows.
