---
description: ZTRE implementation workflow — scout finds context, planner creates plan, worker implements
---
Use the subagent tool with the chain parameter and agentScope "both" to execute this workflow:

1. First, use the "ztre-scout" agent to find all code relevant to: $@
2. Then, use the "ztre-planner" agent to create an implementation plan for "$@" using the context from the previous step (use {previous} placeholder)
3. Finally, use the "ztre-worker" agent to implement the plan from the previous step (use {previous} placeholder)

Execute this as a chain, passing output between steps via {previous}.
