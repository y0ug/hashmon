# hashmon

Tools to monitor hash on VT

## File format

* CSV: `filename,sha256,uuid`
* TXT: one sha256 per line

## Cheat sheet

Convert `builds.json` to CSV:

```sh
jq -r '["uuid","sha256"], (.[] | [.build_id, .hashes.sha256]) | @csv' builds.json > output.csv
jq -r '.[] | .hashes.sha256' ../src/builds/builds.json > output.txt
jq -r '["filename","sha256", "uuid"], (.[] | [.executable, .build_id, .hashes.sha256]) | @csv' ../../builds/builds.json
jq -r '["filename","sha256","uuid"], (.[] | [.executable, .hashes.sha256, .build_id] | join(","))' ../../builds/builds.json
```
