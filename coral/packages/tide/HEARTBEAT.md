# HEARTBEAT.md -- Tide

Daily at configured time:
- Run digest for all monitored topics.
- If priority keyword detected: send breaking alert immediately.

Every 6 hours:
- Check configured sources for new content only.
