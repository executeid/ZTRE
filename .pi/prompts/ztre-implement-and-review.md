---
description: ZTRE review workflow — worker implements, reviewer audits, worker fixes
---
Use the subagent tool with the chain parameter and agentScope "both" to execute this workflow:

1. First, use the "ztre-worker" agent to implement: $@
2. Then, use the "ztre-reviewer" agent to review the changes from the previous step (use {previous} placeholder)
3. Finally, use the "ztre-worker" agent to fix any issues found in the review (use {previous} placeholder)

Execute this as a chain, passing output between steps via {previous}.
