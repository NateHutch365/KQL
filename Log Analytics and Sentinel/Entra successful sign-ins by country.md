# KQL query to count successful interactive and non-interactive sign-ins by country

```kusto
// count successful interactive and non-interactive sign-ins by country
union 
    (SigninLogs 
        | extend Country = tostring(LocationDetails.countryOrRegion)),
    (AADNonInteractiveUserSignInLogs 
        | extend Country = tostring(Location))
| where TimeGenerated > ago(30d)
| where ResultType == 0
| where isnotempty(Country)
| summarize Count = count() by Country
| sort by Count desc
```
