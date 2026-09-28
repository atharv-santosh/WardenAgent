# agent-sandbox

A policy layer between an LLM agent and the tools it can call.

An agent holds your credentials and will act on text it read off a web page if that
text is phrased as an instruction. Prompting does not fix it. This enforces outside
the model: tools are denied by default, every value carries a label saying where it
came from, and data from outside your trust boundary cannot reach a tool that sends
mail or escalates privileges without an explicit, logged declassification. Untrusted
text is parsed by a separate call that can only return a fixed schema.

## Numbers

Same 50 case corpus, four models, undefended against sandboxed:

```
gemini-2.5-flash-lite    74% -> 0%
gemini-2.5-flash         68% -> 0%
gemini-3.5-flash-lite    18% -> 0%
gemini-3.6-flash          4% -> 0%
```

Blocking every untrusted flow also blocks real work. On 30 benign tasks strict
enforcement rejects 33%, and routing through a human approval gate brings that to 7%.

Twelve adaptive attacks written against these defenses. One lands, on both real
models, when the approver rubber stamps. It breaks nothing: the operator asks to
write to a contact named in an email, the attacker wrote the email.

## Running it

```
uv pip install -e ".[web,gemini]"
sbx serve
```

Then http://127.0.0.1:8711 to write a payload and watch both agents handle it.
`sbx redteam` runs the corpus. Without credentials everything runs on a simulator.

Tools are simulated. Nothing sends real mail or makes real requests, whatever a
payload asks for.

MEASUREMENTS.md has the full tables. THREAT-MODEL.md says what this does not stop.
