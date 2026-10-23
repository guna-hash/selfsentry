# Follow-up VM verification — 23 October 2026

- PASS: `state/evaluation/final-checks-20261023T164633Z/results.json`
  - SHA256: `bda91b3e5ddd7cdd7482ca78ffc217547b83c4cb8c4ab8bd1705332d0df2a300`
- PASS: `state/evaluation/postgres-acceptance-20261023T165244023458Z/results.json`
  - SHA256: `6b82ddbcb76376c0ab7cd4a202bc60c6c59dfc4d077af7063a3767a77b362def`
- PASS: `state/evaluation/postgres-concurrency-20261023T165346964953Z/results.json`
  - SHA256: `1ec62adbf8a9110920fb6b0163c47961783b4634fa1d316e9948de44992d3904`
- PASS: `state/evaluation/workload-check-20261023T165440379330Z/results.json`
  - SHA256: `97974cdccef92c06ca8d110b11ebe6a975988d60c7387da79190034cdc384565`

Live schema comparison matched; git diff --check was clean.
Post-update runtime status reported healthy.
Native Falco retirement, sustained-load testing, full application restore
and representative detection-quality evaluation remain unverified.
Private database dumps and raw runtime evidence remain outside Git.

## Native reload and retirement recovery verification

- PASS: `state/evaluation/native-reload-20261023T170913689070Z/results.json`
  - SHA256: `3ee9c72f185fde926f01225816d5f48c6ee837d40bd22ff9131d9f41f5f00648`
- PASS: `state/evaluation/native-retirement-5-20261023T172020188631Z/results.json`
  - SHA256: `186a27f0183ae859a8666f505769f8084d454c5fe1523888fc243ed61823fa7c`

Rule 5 was retired and explicitly restored; original file hash matched.
Retirement endpoint was disabled and the temporary Falco override removed.
Falco resumed its original startup command and reported active/running.
Before-and-after detection behavior and failure recovery remain unverified.

## Journal archive-copy verification

- PASS: `state/evaluation/journal-archive-check-20261023T174519197416Z.json`
- SHA256: `4ae117026158ca49410b4b6b0fdb336aa9576355118f075a8d18b6a914d67b4a`
- Archived and verified 1,000 payloads on a disposable copy.
- Logical events, replay keys, alerts and protected tables preserved.
- Original snapshot unchanged; monitor healthy without restarting.
- Live retention and whole-application restore remain unverified.
