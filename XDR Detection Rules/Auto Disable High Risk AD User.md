```kql
// AH custom detection: disable when user risk flipped HIGH within the lookback (e.g., last 1h)
// IMPORTANT: When creating the detection rule, set the frequency to run every hour. 
// At 1h frequency, Advanced Hunting evaluates the last 4h of data (lookback).
// This query ensures it only triggers if a user's risk was set to HIGH within a 1h window.
// Requires Defender for Identity
let RiskWindow = 1h;
IdentityLogonEvents
| where Timestamp > ago(30d)   // wide window just to borrow a ReportId (AH requires it)
| summarize arg_max(Timestamp, ReportId, AccountUpn, AccountObjectId, Application, LogonType)
          by AccountObjectId
| join kind=inner (
    IdentityInfo
    | summarize ArgTS = arg_max(Timestamp, RiskLevel, RiskLevelDetails, OnPremSid) by AccountUpn, AccountObjectId
    | where RiskLevel =~ "high" or RiskLevelDetails has "adminConfirmedUserCompromised"
    | where ArgTS > ago(RiskWindow)
    | project AccountObjectId, AccountUpn, OnPremSid,       // <-- include SID
              RiskLevel, RiskLevelDetails, RiskSetTime = ArgTS
) on AccountObjectId
// Exclusions: update these!
| where AccountUpn !in~ ("breakglass1@contoso.com","breakglass2@contoso.com")
| project
    ReportId,                 // REQUIRED for custom detections
    Timestamp,                // REQUIRED (keep name exactly)
    AccountUpn, AccountObjectId,
    OnPremSid,                // <-- REQUIRED for the "Disable user" action
    RiskSetTime, RiskLevel, RiskLevelDetails,
    Application, LogonType
```