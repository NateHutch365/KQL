```kql
//Advanced Hunting query to detect NTLM usage in the environment
// All credit for this query goes to Matt Zorich
IdentityLogonEvents
| where Timestamp > ago(7d)
| where ActionType == "LogonSuccess"
| where Protocol =~ "Ntlm"
| where LogonType == "Credentials validation"
| summarize ['Target Device List']=make_set(DestinationDeviceName), ['Target Device Count']=dcount(DestinationDeviceName) by DeviceName, AccountName
| sort by ['Target Device Count'] desc 
```
