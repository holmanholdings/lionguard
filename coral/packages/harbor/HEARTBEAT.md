# HEARTBEAT.md -- Harbor

Every 15 minutes:
- Scan open tickets/escalations for stalled conversations.
- If >3 failed attempts on same issue: auto-escalate with full context.
- If billing dispute > $[AMOUNT_THRESHOLD]: flag for human.

Daily at 8 AM:
- Send operator summary: "X tickets handled, Y escalated, Z resolved."
