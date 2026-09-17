"""
Alert & Notification Module (Member 6).

Turns confirmed threat/detection events from the Threat Monitoring module
(Member 5) into persisted, queryable Alert records, notifies recipients,
and exposes REST APIs for the frontend (Member 7).

Entry points:
    router.py   REST API under /api/v1/alerts
    service.py  Core logic (create with dedup, list with RBAC scoping, resolve)
    adapters.py Translates a detection event into an AlertCreate payload —
                used by app.modules.threat_monitoring.alert_integration
"""
