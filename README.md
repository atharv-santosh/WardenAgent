# agent-sandbox

A policy layer that sits between an LLM agent and the tools it can call.

The problem it addresses is that an agent is a confused deputy. It holds your
credentials and your permissions, and it will act on text that came from a web
page or an email if that text is phrased as an instruction. Prompt engineering
does not fix this, because the model has no reliable way to tell your
instructions apart from text it just read.

So this enforces outside the model instead. Tools are denied by default and
granted explicitly. Every value carries a label saying where it came from, and
those labels propagate, so data that originated outside your trust boundary
cannot reach a tool that can send mail, write files or escalate privileges
without an explicit, logged declassification step. Untrusted text is never
parsed by the privileged agent directly; it goes through a separate constrained
call that can only return a fixed schema.

## Numbers

Against a 50 case corpus run on real Gemini models, the undefended agent was
tricked 74% of the time on gemini-2.5-flash-lite and 68% on gemini-2.5-flash.
Behind the sandbox, neither model was tricked once.

That is not free. Blocking every untrusted-to-privileged flow also blocks real
work, like reading a customer email and forwarding a summary. Measured on 30
benign tasks, strict enforcement rejects 33% of them. Routing the decision
through a human approval gate brings that to 7%. The full breakdown, including
a case where the quarantine path gave no benefit at all against a real model,
is in MEASUREMENTS.md.

## Running it

```
uv pip install -e ".[web,gemini]"
sbx serve
```

Open http://127.0.0.1:8711, write an injection payload, and watch the
undefended and sandboxed agents handle it side by side.

Without Google Cloud credentials everything still runs on a deterministic
simulator, so the tests and the offline corpus work with no setup. To use real
models, run `gcloud auth application-default login` and set
`GOOGLE_CLOUD_PROJECT`.

The command line works too: `sbx redteam` runs the corpus, `sbx policy check`
validates a policy file.

## A note on the tools

Every tool the agent can call is simulated in memory. Nothing sends real email
or makes real network requests, whatever an injected payload asks for. That is
deliberate, since the point of the app is to let people type hostile input into
an agent that will genuinely obey it.

THREAT-MODEL.md is blunt about what this does not defend against, including
adaptive attackers who have read this code.
