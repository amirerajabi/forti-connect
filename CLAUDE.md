@AGENTS.md

## Claude Code notes

- `.claude/launch.json` defines `dev` for the browser preview (`scripts/run.mjs browser`, UI on 5174, engine on 7330).
  RayConnect uses the same ports: stop one before starting the other.
- No real FortiGate is available for testing here; the engine tests' fake VPN program (`engine/test/fixtures/fake-vpn.mjs`)
  is the stand-in. Say so when a change could only be checked against it.
- Update [docs/STATUS.md](docs/STATUS.md) when you finish something listed there or leave work unfinished.
