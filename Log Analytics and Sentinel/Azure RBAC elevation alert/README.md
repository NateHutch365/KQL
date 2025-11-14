# KQL Detection: Global Administrator Elevation to **User Access Administrator**

This README describes a KQL query for identifying when a **Global Administrator** uses the **Access Management for Azure Resources** toggle in Microsoft Entra ID to elevate their access and grant themselves the **User Access Administrator** role at the Azure root scope (management group and all subscriptions).

The query is designed to run in:

* **Azure Monitor Log Analytics** workspaces, or
* **Microsoft Sentinel** (Analytics, Hunting, or Log Viewer)

---

## 1. Purpose

When a Global Administrator activates the **Access management for Azure resources** option in Entra ID, they are granted the **User Access Administrator** role at the root scope. This allows them to view and manage **all** Azure subscriptions and management groups in the tenant, even if they previously lacked access.

This action:

* Bypasses the principle of least privilege and limited standing access.
* Is high-impact if a Global Administrator account is compromised.
* Should be tightly monitored and investigated whenever it occurs.

This KQL query identifies these elevation events in the **Entra ID Audit Logs**.

---

## 2. Prerequisites

To use this query, the following conditions **must** be met:

1. **Log Source**

   * Microsoft Entra ID **Audit Logs** must be sent to the target Log Analytics workspace.
   * This is typically configured via the **Diagnostic Settings** for Entra ID, with the **AuditLogs** category enabled.

2. **Table Availability**

   * The workspace must contain the **`AuditLogs`** table.

3. **Permissions**

   * You must have permission to query the workspace (for example, Log Analytics Reader, Sentinel Reader/Contributor, or equivalent RBAC role).

---

## 3. The KQL Query

```kusto
AuditLogs
| where Category == "AzureRBACRoleManagementElevateAccess"
| where ActivityDisplayName == "User has elevated their access to User Access Administrator for their Azure Resources"
| extend Actor = tostring(InitiatedBy.user.displayName)
| extend ActorUPN = tostring(InitiatedBy.user.userPrincipalName)
| extend ActorId = tostring(InitiatedBy.user.id)
| extend Operation = tostring(OperationName)
| extend IPAddress = tostring(InitiatedBy.user.ipAddress)
| extend AppId = tostring(InitiatedBy.app.appId)
| project TimeGenerated, ActivityDisplayName, Category, Operation, Actor, ActorUPN, ActorId, IPAddress, AppId, Result, ResultReason, CorrelationId
| order by TimeGenerated desc
```

---

## 4. How It Works

The query:

1. **Filters the Audit Logs**

   * `Category == "AzureRBACRoleManagementElevateAccess"`

     * Narrows to the Entra ID audit category related to Azure RBAC elevation.
   * `ActivityDisplayName == "User has elevated their access to User Access Administrator for their Azure Resources"`

     * Specifically targets the elevation action triggered by the **Access management for Azure resources** toggle.

2. **Extracts Actor and Context Information**

   * Uses `extend` to extract and normalise key fields from the nested `InitiatedBy` and `app` objects:

     * `Actor` – Display name of the user who elevated access.
     * `ActorUPN` – User Principal Name of the actor.
     * `ActorId` – Object ID of the actor in Entra ID.
     * `Operation` – High-level operation name.
     * `IPAddress` – IP address used for the action.
     * `AppId` – Application ID if the action was initiated via an app.

3. **Selects Relevant Output Columns**

   * `project` limits the output to the most relevant investigation fields.

4. **Sorts Events**

   * `order by TimeGenerated desc` shows the **most recent** elevation events first.

---

## 5. Running the Query

### 5.1 In Log Analytics

1. Open the **Log Analytics workspace** that receives Entra ID Audit Logs.
2. Go to **Logs**.
3. Paste the KQL query into the query editor.
4. Optionally adjust the **Time range** (e.g. Last 24 hours, Last 7 days).
5. Select **Run**.

### 5.2 In Microsoft Sentinel

You can use the same query in multiple places:

* **Logs**: For ad-hoc investigation or hunting.
* **Hunting**: Save as a Hunting query for ongoing investigations.
* **Analytics rule**: Use it as the basis of a scheduled analytics rule to generate incidents.

Steps (example for Logs):

1. In the Sentinel workspace, select **Logs**.
2. Ensure the correct workspace is selected (the one with Entra ID Audit Logs).
3. Paste the query and run it as above.

---

## 6. Interpreting the Results

Each row represents a **single elevation event** where a user has enabled the Access Management for Azure Resources toggle.

Key columns:

* **TimeGenerated** – Time the event was logged.
* **ActivityDisplayName** – Human-readable description of the activity; should match the elevation action string.
* **Category** – Should be `AzureRBACRoleManagementElevateAccess`.
* **Operation** – Operation name from the audit log.
* **Actor** – Display name of the user who elevated access.
* **ActorUPN** – UPN of the user; use this to identify the account.
* **ActorId** – Entra ID object ID; useful for cross-referencing with identity tools.
* **IPAddress** – Source IP address used for the operation.
* **AppId** – Application ID if the action was initiated via an app.
* **Result / ResultReason** – Indicates whether the operation succeeded or failed, and why.
* **CorrelationId** – Correlation identifier for grouping related log entries across services.

Recommended follow-up actions when a **successful** event is observed:

* Confirm the user is an authorised Global Administrator.
* Validate whether the elevation was expected and approved (e.g. change ticket, CAB request).
* Check for subsequent role assignments or suspicious activity in Azure.
* Ensure the elevated access is revoked once no longer required.

---

## 7. Using This Query in an Analytics Rule (Sentinel)

To continuously monitor for this activity, you can convert this query into a scheduled analytics rule:

* **Rule type**: Scheduled query rule.
* **Query**: Use the exact KQL from this README.
* **Schedule**: For example, run every 5–15 minutes, looking back 1–2 hours.
* **Alert threshold**: Alert on **any** result (since this is a high-impact operation).
* **Entity mapping**:

  * Map `ActorUPN` to **Account**.
  * Map `IPAddress` to **IP**.
  * Map `ActorId` to **Account object ID** if supported.

This ensures that any use of the Access Management elevation feature generates an incident for investigation.

---

## 8. Limitations and Considerations

* The query only works if **Entra ID Audit Logs** are being ingested into the workspace.
* If the **ActivityDisplayName** or **Category** values change in future service updates, the query may need to be updated.
* The query assumes that only authorised Global Administrators can perform this action. If role design deviates from this, you may need additional logic to distinguish expected versus unexpected usage.

---

## 9. Change Log

* **v1.0** – Initial version of the README and KQL query for detecting Global Administrator elevation to User Access Administrator via Access Management for Azure Resources.
