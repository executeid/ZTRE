---
description: ZTRE scout and plan — fast recon then implementation plan, no code changes
---
Use the subagent tool with the chain parameter and agentScope "both" to execute this workflow:

1. First, use the "ztre-scout" agent to find all code relevant to: $@
2. Then, use the "ztre-planner" agent to create a detailed implementation plan for "$@" using the context from the previous step (use {previous} placeholder)

Execute this as a chain, passing output between steps via {previous}. Do NOT implement — planning only.
