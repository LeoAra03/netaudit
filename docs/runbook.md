# Runbook

## The gate fails on main

1. `netaudit scan <config> --format json` locally and confirm the finding is real.
2. Real: fix the config, not the threshold. Threshold changes are a separate PR with
   justification.
3. False positive: open an issue with the config snippet, add a negative fixture, tighten
   `match`.

## Deploy is red

1. Check the Trivy gate first; a new HIGH in a base image is the usual cause.
2. Bump the base image, rebuild, re-tag.
3. OIDC failure: confirm the federated credential subject still matches the branch.

## Demo is down

`az containerapp revision list -g rg-netaudit -n netaudit`. Scale-to-zero cold start is
expected; if the revision is failed, roll back to the previous one and read the log
stream.
