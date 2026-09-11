# Open-Source Launch Plan

## Release gate

Do not announce the project until:

- The public name is cleared and reserved.
- A clean machine can install the wheel and run the quickstart.
- CI passes on every supported Python version.
- Two practitioners outside the project have reviewed the API and reports.
- Private vulnerability reporting is enabled.
- The repository has a release tag, signed artifacts, checksums, and a changelog.
- Examples use only synthetic data and authorized targets.

## Launch assets

- A 60 to 90 second terminal recording showing `init`, `run`, and a Markdown report
- One architecture diagram
- One example of a vulnerable local result and a corrected result
- A five-minute quickstart
- A technical article explaining why oracles and evidence matter more than a prompt list
- A public roadmap with three beginner-friendly issues

## LinkedIn launch draft

Today Advent Cybersecurity is open-sourcing **advent-prompt-pwn**, a Python toolkit for authorized adversarial testing of AI systems.

We wanted something that felt natural to security engineers: define a target, compose an attack strategy, state the success condition, run the test, and retain evidence that another assessor can review.

The first release includes:

- Direct and indirect prompt-injection strategies
- Controlled multi-turn testing
- Synthetic canary and tool-call detection
- Local Ollama and OpenAI-compatible targets
- Explicit remote host allowlists and request budgets
- JSON, JSONL, safely escaped HTML, Markdown, JUnit, and SARIF reports
- No telemetry

This is an early release. We are looking for practitioners who will challenge the API, find weak assumptions, and contribute realistic test cases that can be shared safely.

Repository: {REPOSITORY_URL}
Quickstart: {QUICKSTART_URL}

Use it only on systems you own or have explicit permission to assess.

#AISecurity #AIRedTeam #PromptInjection #OpenSource #Cybersecurity

## Follow-up posts

1. Why a jailbreak string without an oracle is not a repeatable security test.
2. How exact endpoint allowlists reduce red-team accidents.
3. A local Ollama demonstration using a synthetic canary.
4. How to write a third-party strategy plugin.
5. What the project learned from its first external assessment.

## Measures worth tracking

- Successful clean installs
- Quickstart completion rate
- Actionable issues from practitioners
- External strategy plugins
- Repeat contributors
- Documented authorized assessments

Stars and impressions can show reach, but they do not establish that the toolkit is reliable.
