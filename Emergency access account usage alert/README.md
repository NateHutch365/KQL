# KQL query for usage of emergency access (break glass) accounts

To be used as a log analytics query as an alert rule with the following settings:

1. Signal name: Custom log search
2. Query: See query
3. Measurement: Aggregation granularity: 5 minutes
4. Alert logic: Operator: Greater than, Threshold value: 0, Frequency of evaluation: 5 minutes
5. Action group: Create new action group called "BreakGlassNotifications"
6. Email notify: Provide appropriate email address
7. Alert rule details: Severity: Critical, Alert rule name: Emergency Access Account Monitor, Alert rule description: "This alert will fire off in the event that an emergency access account is used for sign-in. These accounts should only be used in emergency situations and with prior approval."