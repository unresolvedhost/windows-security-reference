class WindowsEventsLookup {
    constructor() {
        this.events = [];
        this.filteredEvents = [];
        this.allFieldNames = new Set();
        this.allCategories = new Set();
        this.allSubcategories = new Set();
        
        this.initializeElements();
        this.loadData();
        this.setupEventListeners();
    }

    initializeElements() {
        this.eventIdInput = document.getElementById('eventId');
        this.categorySelect = document.getElementById('category');
        this.subcategorySelect = document.getElementById('subcategory');
        this.messageSearchInput = document.getElementById('messageSearch');
        this.fieldNamesContainer = document.getElementById('fieldNamesContainer');
        this.clearFiltersBtn = document.getElementById('clearFilters');
        this.resultsCount = document.getElementById('resultsCount');
        this.resultsTable = document.getElementById('resultsTable');
    }

    loadData() {
        try {
            this.events = [
                            {
                                "event_id": 4610,
                                "category": "System",
                                "subcategory": "Security System Extension",
                                "message_summary": "An authentication package has been loaded by the Local Security Authority.",
                                "field_count": 1,
                                "field_names": [
                                "AuthenticationPackageName"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4610"
                            },
                            {
                                "event_id": 4611,
                                "category": "System",
                                "subcategory": "Security System Extension",
                                "message_summary": "A trusted logon process has been registered with the Local Security Authority.",
                                "field_count": 5,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "LogonProcessName"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4611"
                            },
                            {
                                "event_id": 4612,
                                "category": "System",
                                "subcategory": "System Integrity",
                                "message_summary": "Internal resources allocated for the queuing of audit messages have been exhausted, leading to the loss of some audits.",
                                "field_count": 1,
                                "field_names": [
                                "AuditsDiscarded"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4612"
                            },
                            {
                                "event_id": 4614,
                                "category": "System",
                                "subcategory": "Security System Extension",
                                "message_summary": "A notification package has been loaded by the Security Account Manager.",
                                "field_count": 1,
                                "field_names": [
                                "NotificationPackageName"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4614"
                            },
                            {
                                "event_id": 4615,
                                "category": "System",
                                "subcategory": "System Integrity",
                                "message_summary": "Invalid use of LPC port.",
                                "field_count": 8,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "InvalidCallName",
                                "ServerPortName",
                                "ProcessId",
                                "ProcessName"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4615"
                            },
                            {
                                "event_id": 4616,
                                "category": "System",
                                "subcategory": "Security State Change",
                                "message_summary": "The system time was changed.",
                                "field_count": 8,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "PreviousTime",
                                "NewTime",
                                "ProcessId",
                                "ProcessName"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4616"
                            },
                            {
                                "event_id": 4618,
                                "category": "System",
                                "subcategory": "System Integrity",
                                "message_summary": "A monitored security event pattern has occurred.",
                                "field_count": 8,
                                "field_names": [
                                "EventId",
                                "ComputerName",
                                "TargetUserSid",
                                "TargetUserName",
                                "TargetUserDomain",
                                "TargetLogonId",
                                "EventCount",
                                "Duration"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4618"
                            },
                            {
                                "event_id": 4621,
                                "category": "System",
                                "subcategory": "Security State Change",
                                "message_summary": "Administrator recovered system from CrashOnAuditFail. Users who are not administrators will now be allowed to log on. Some auditable activity might not have been recorded.",
                                "field_count": 1,
                                "field_names": [
                                "CrashOnAuditFailValue"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4621"
                            },
                            {
                                "event_id": 4622,
                                "category": "System",
                                "subcategory": "Security System Extension",
                                "message_summary": "A security package has been loaded by the Local Security Authority.",
                                "field_count": 1,
                                "field_names": [
                                "SecurityPackageName"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4622"
                            },
                            {
                                "event_id": 4624,
                                "category": "Logon/Logoff",
                                "subcategory": "Logon",
                                "message_summary": "An account was successfully logged on.",
                                "field_count": 20,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "TargetUserSid",
                                "TargetUserName",
                                "TargetDomainName",
                                "TargetLogonId",
                                "LogonType",
                                "LogonProcessName",
                                "AuthenticationPackageName",
                                "WorkstationName",
                                "LogonGuid",
                                "TransmittedServices",
                                "LmPackageName",
                                "KeyLength",
                                "ProcessId",
                                "ProcessName",
                                "IpAddress",
                                "IpPort"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624"
                            },
                            {
                                "event_id": 4625,
                                "category": "Logon/Logoff",
                                "subcategory": "Logon",
                                "message_summary": "An account failed to log on.",
                                "field_count": 21,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "TargetUserSid",
                                "TargetUserName",
                                "TargetDomainName",
                                "Status",
                                "FailureReason",
                                "SubStatus",
                                "LogonType",
                                "LogonProcessName",
                                "AuthenticationPackageName",
                                "WorkstationName",
                                "TransmittedServices",
                                "LmPackageName",
                                "KeyLength",
                                "ProcessId",
                                "ProcessName",
                                "IpAddress",
                                "IpPort"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625"
                            },
                            {
                                "event_id": 4634,
                                "category": "Logon/Logoff",
                                "subcategory": "Logoff",
                                "message_summary": "An account was logged off.",
                                "field_count": 5,
                                "field_names": [
                                "TargetUserSid",
                                "TargetUserName",
                                "TargetDomainName",
                                "TargetLogonId",
                                "LogonType"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4634"
                            },
                            {
                                "event_id": 4646,
                                "category": "Logon/Logoff",
                                "subcategory": "IPsec Main Mode",
                                "message_summary": "%1",
                                "field_count": 1,
                                "field_names": [
                                "notification"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4646"
                            },
                            {
                                "event_id": 4647,
                                "category": "Logon/Logoff",
                                "subcategory": "Logoff",
                                "message_summary": "User initiated logoff.",
                                "field_count": 4,
                                "field_names": [
                                "TargetUserSid",
                                "TargetUserName",
                                "TargetDomainName",
                                "TargetLogonId"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4647"
                            },
                            {
                                "event_id": 4648,
                                "category": "Logon/Logoff",
                                "subcategory": "Logon",
                                "message_summary": "A logon was attempted using explicit credentials.",
                                "field_count": 14,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "LogonGuid",
                                "TargetUserName",
                                "TargetDomainName",
                                "TargetLogonGuid",
                                "TargetServerName",
                                "TargetInfo",
                                "ProcessId",
                                "ProcessName",
                                "IpAddress",
                                "IpPort"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4648"
                            },
                            {
                                "event_id": 4649,
                                "category": "Logon/Logoff",
                                "subcategory": "Other Logon/Logoff Events",
                                "message_summary": "A replay attack was detected.",
                                "field_count": 13,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "TargetUserName",
                                "TargetDomainName",
                                "RequestType",
                                "LogonProcessName",
                                "AuthenticationPackage",
                                "WorkstationName",
                                "TransmittedServices",
                                "ProcessId",
                                "ProcessName"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4649"
                            },
                            {
                                "event_id": 4650,
                                "category": "Logon/Logoff",
                                "subcategory": "IPsec Main Mode",
                                "message_summary": "An IPsec Main Mode security association was established. Extended Mode was not enabled. Certificate authentication was not used.",
                                "field_count": 17,
                                "field_names": [
                                "LocalMMPrincipalName",
                                "RemoteMMPrincipalName",
                                "LocalAddress",
                                "LocalKeyModPort",
                                "RemoteAddress",
                                "RemoteKeyModPort",
                                "KeyModName",
                                "MMAuthMethod",
                                "MMCipherAlg",
                                "MMIntegrityAlg",
                                "DHGroup",
                                "MMLifetime",
                                "QMLimit",
                                "Role",
                                "MMImpersonationState",
                                "MMFilterID",
                                "MMSAID"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4650"
                            },
                            {
                                "event_id": 4651,
                                "category": "Logon/Logoff",
                                "subcategory": "IPsec Main Mode",
                                "message_summary": "An IPsec Main Mode security association was established. Extended Mode was not enabled. A certificate was used for authentication.",
                                "field_count": 23,
                                "field_names": [
                                "LocalMMPrincipalName",
                                "LocalMMCertHash",
                                "LocalMMIssuingCA",
                                "LocalMMRootCA",
                                "RemoteMMPrincipalName",
                                "RemoteMMCertHash",
                                "RemoteMMIssuingCA",
                                "RemoteMMRootCA",
                                "LocalAddress",
                                "LocalKeyModPort",
                                "RemoteAddress",
                                "RemoteKeyModPort",
                                "KeyModName",
                                "MMAuthMethod",
                                "MMCipherAlg",
                                "MMIntegrityAlg",
                                "DHGroup",
                                "MMLifetime",
                                "QMLimit",
                                "Role",
                                "MMImpersonationState",
                                "MMFilterID",
                                "MMSAID"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4651"
                            },
                            {
                                "event_id": 4652,
                                "category": "Logon/Logoff",
                                "subcategory": "IPsec Main Mode",
                                "message_summary": "An IPsec Main Mode negotiation failed.",
                                "field_count": 22,
                                "field_names": [
                                "LocalMMPrincipalName",
                                "LocalMMCertHash",
                                "LocalMMIssuingCA",
                                "LocalMMRootCA",
                                "RemoteMMPrincipalName",
                                "RemoteMMCertHash",
                                "RemoteMMIssuingCA",
                                "RemoteMMRootCA",
                                "LocalAddress",
                                "LocalKeyModPort",
                                "RemoteAddress",
                                "RemoteKeyModPort",
                                "KeyModName",
                                "FailurePoint",
                                "FailureReason",
                                "MMAuthMethod",
                                "State",
                                "Role",
                                "MMImpersonationState",
                                "MMFilterID",
                                "InitiatorCookie",
                                "ResponderCookie"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4652"
                            },
                            {
                                "event_id": 4653,
                                "category": "Logon/Logoff",
                                "subcategory": "IPsec Main Mode",
                                "message_summary": "An IPsec Main Mode negotiation failed.",
                                "field_count": 16,
                                "field_names": [
                                "LocalMMPrincipalName",
                                "RemoteMMPrincipalName",
                                "LocalAddress",
                                "LocalKeyModPort",
                                "RemoteAddress",
                                "RemoteKeyModPort",
                                "KeyModName",
                                "FailurePoint",
                                "FailureReason",
                                "MMAuthMethod",
                                "State",
                                "Role",
                                "MMImpersonationState",
                                "MMFilterID",
                                "InitiatorCookie",
                                "ResponderCookie"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4653"
                            },
                            {
                                "event_id": 4654,
                                "category": "Logon/Logoff",
                                "subcategory": "IPsec Quick Mode",
                                "message_summary": "An IPsec Quick Mode negotiation failed.",
                                "field_count": 21,
                                "field_names": [
                                "LocalAddress",
                                "LocalAddressMask",
                                "LocalPort",
                                "LocalTunnelEndpoint",
                                "RemoteAddress",
                                "RemoteAddressMask",
                                "RemotePort",
                                "RemoteTunnelEndpoint",
                                "Protocol",
                                "RemotePrivateAddress",
                                "KeyModName",
                                "FailurePoint",
                                "FailureReason",
                                "Mode",
                                "State",
                                "Role",
                                "MessageID",
                                "QMFilterID",
                                "MMSAID",
                                "TunnelId",
                                "TrafficSelectorId"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4654"
                            },
                            {
                                "event_id": 4655,
                                "category": "Logon/Logoff",
                                "subcategory": "IPsec Main Mode",
                                "message_summary": "An IPsec Main Mode security association ended.",
                                "field_count": 4,
                                "field_names": [
                                "LocalAddress",
                                "RemoteAddress",
                                "KeyModName",
                                "MMSAID"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4655"
                            },
                            {
                                "event_id": 4656,
                                "category": "Object Access",
                                "subcategory": "Handle Manipulation",
                                "message_summary": "A handle to an object was requested.",
                                "field_count": 16,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "ObjectServer",
                                "ObjectType",
                                "ObjectName",
                                "HandleId",
                                "TransactionId",
                                "AccessList",
                                "AccessReason",
                                "AccessMask",
                                "PrivilegeList",
                                "RestrictedSidCount",
                                "ProcessId",
                                "ProcessName"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4656"
                            },
                            {
                                "event_id": 4657,
                                "category": "Object Access",
                                "subcategory": "Registry",
                                "message_summary": "A registry value was modified.",
                                "field_count": 14,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "ObjectName",
                                "ObjectValueName",
                                "HandleId",
                                "OperationType",
                                "OldValueType",
                                "OldValue",
                                "NewValueType",
                                "NewValue",
                                "ProcessId",
                                "ProcessName"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4657"
                            },
                            {
                                "event_id": 4658,
                                "category": "Object Access",
                                "subcategory": "Handle Manipulation",
                                "message_summary": "The handle to an object was closed.",
                                "field_count": 8,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "ObjectServer",
                                "HandleId",
                                "ProcessId",
                                "ProcessName"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4658"
                            },
                            {
                                "event_id": 4659,
                                "category": "Object Access",
                                "subcategory": "SAM",
                                "message_summary": "A handle to an object was requested with intent to delete.",
                                "field_count": 13,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "ObjectServer",
                                "ObjectType",
                                "ObjectName",
                                "HandleId",
                                "TransactionId",
                                "AccessList",
                                "AccessMask",
                                "PrivilegeList",
                                "ProcessId"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4659"
                            },
                            {
                                "event_id": 4659,
                                "category": "Object Access",
                                "subcategory": "Kernel",
                                "message_summary": "A handle to an object was requested with intent to delete.",
                                "field_count": 13,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "ObjectServer",
                                "ObjectType",
                                "ObjectName",
                                "HandleId",
                                "TransactionId",
                                "AccessList",
                                "AccessMask",
                                "PrivilegeList",
                                "ProcessId"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4659"
                            },
                            {
                                "event_id": 4660,
                                "category": "Object Access",
                                "subcategory": "SAM",
                                "message_summary": "An object was deleted.",
                                "field_count": 9,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "ObjectServer",
                                "HandleId",
                                "ProcessId",
                                "ProcessName",
                                "TransactionId"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4660"
                            },
                            {
                                "event_id": 4660,
                                "category": "Object Access",
                                "subcategory": "Kernel",
                                "message_summary": "An object was deleted.",
                                "field_count": 9,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "ObjectServer",
                                "HandleId",
                                "ProcessId",
                                "ProcessName",
                                "TransactionId"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4660"
                            },
                            {
                                "event_id": 4661,
                                "category": "Object Access",
                                "subcategory": "SAM",
                                "message_summary": "A handle to an object was requested.",
                                "field_count": 16,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "ObjectServer",
                                "ObjectType",
                                "ObjectName",
                                "HandleId",
                                "TransactionId",
                                "AccessList",
                                "AccessMask",
                                "PrivilegeList",
                                "Properties",
                                "RestrictedSidCount",
                                "ProcessId",
                                "ProcessName"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4661"
                            },
                            {
                                "event_id": 4661,
                                "category": "Object Access",
                                "subcategory": "Kernel",
                                "message_summary": "A handle to an object was requested.",
                                "field_count": 16,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "ObjectServer",
                                "ObjectType",
                                "ObjectName",
                                "HandleId",
                                "TransactionId",
                                "AccessList",
                                "AccessMask",
                                "PrivilegeList",
                                "Properties",
                                "RestrictedSidCount",
                                "ProcessId",
                                "ProcessName"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4661"
                            },
                            {
                                "event_id": 4662,
                                "category": "DS Access",
                                "subcategory": "Directory Service Access",
                                "message_summary": "An operation was performed on an object.",
                                "field_count": 14,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "ObjectServer",
                                "ObjectType",
                                "ObjectName",
                                "OperationType",
                                "HandleId",
                                "AccessList",
                                "AccessMask",
                                "Properties",
                                "AdditionalInfo",
                                "AdditionalInfo2"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4662"
                            },
                            {
                                "event_id": 4663,
                                "category": "Object Access",
                                "subcategory": "SAM",
                                "message_summary": "An attempt was made to access an object.",
                                "field_count": 12,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "ObjectServer",
                                "ObjectType",
                                "ObjectName",
                                "HandleId",
                                "AccessList",
                                "AccessMask",
                                "ProcessId",
                                "ProcessName"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4663"
                            },
                            {
                                "event_id": 4663,
                                "category": "Object Access",
                                "subcategory": "Kernel",
                                "message_summary": "An attempt was made to access an object.",
                                "field_count": 12,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "ObjectServer",
                                "ObjectType",
                                "ObjectName",
                                "HandleId",
                                "AccessList",
                                "AccessMask",
                                "ProcessId",
                                "ProcessName"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4663"
                            },
                            {
                                "event_id": 4664,
                                "category": "Object Access",
                                "subcategory": "File System",
                                "message_summary": "An attempt was made to create a hard link.",
                                "field_count": 7,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "FileName",
                                "LinkName",
                                "TransactionId"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4664"
                            },
                            {
                                "event_id": 4665,
                                "category": "Object Access",
                                "subcategory": "Application Generated",
                                "message_summary": "An attempt was made to create an application client context.",
                                "field_count": 6,
                                "field_names": [
                                "AppName",
                                "AppInstance",
                                "ClientName",
                                "ClientDomain",
                                "ClientLogonId",
                                "Status"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4665"
                            },
                            {
                                "event_id": 4666,
                                "category": "Object Access",
                                "subcategory": "Application Generated",
                                "message_summary": "An application attempted an operation:",
                                "field_count": 11,
                                "field_names": [
                                "AppName",
                                "AppInstance",
                                "ObjectName",
                                "ScopeName",
                                "ClientName",
                                "ClientDomain",
                                "ClientLogonId",
                                "Role",
                                "Group",
                                "OperationName",
                                "OperationId"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4666"
                            },
                            {
                                "event_id": 4667,
                                "category": "Object Access",
                                "subcategory": "Application Generated",
                                "message_summary": "An application client context was deleted.",
                                "field_count": 5,
                                "field_names": [
                                "AppName",
                                "AppInstance",
                                "ClientName",
                                "ClientDomain",
                                "ClientLogonId"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4667"
                            },
                            {
                                "event_id": 4668,
                                "category": "Object Access",
                                "subcategory": "Application Generated",
                                "message_summary": "An application was initialized.",
                                "field_count": 6,
                                "field_names": [
                                "AppName",
                                "AppInstance",
                                "ClientName",
                                "ClientDomain",
                                "ClientLogonId",
                                "StoreUrl"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4668"
                            },
                            {
                                "event_id": 4670,
                                "category": "Policy Change",
                                "subcategory": "Subcategory (special)",
                                "message_summary": "Permissions on an object were changed.",
                                "field_count": 12,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "ObjectServer",
                                "ObjectType",
                                "ObjectName",
                                "HandleId",
                                "OldSd",
                                "NewSd",
                                "ProcessId",
                                "ProcessName"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4670"
                            },
                            {
                                "event_id": 4671,
                                "category": "Object Access",
                                "subcategory": "Other Object Access Events",
                                "message_summary": "An application attempted to access a blocked ordinal through the TBS.",
                                "field_count": 5,
                                "field_names": [
                                "CallerUserSid",
                                "CallerUserName",
                                "CallerDomainName",
                                "CallerLogonId",
                                "Ordinal"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4671"
                            },
                            {
                                "event_id": 4672,
                                "category": "Privilege Use",
                                "subcategory": "Sensitive Privilege Use / Non Sensitive Privilege Use",
                                "message_summary": "Special privileges assigned to new logon.",
                                "field_count": 5,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "PrivilegeList"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4672"
                            },
                            {
                                "event_id": 4673,
                                "category": "Privilege Use",
                                "subcategory": "Sensitive Privilege Use / Non Sensitive Privilege Use",
                                "message_summary": "A privileged service was called.",
                                "field_count": 9,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "ObjectServer",
                                "Service",
                                "PrivilegeList",
                                "ProcessId",
                                "ProcessName"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4673"
                            },
                            {
                                "event_id": 4674,
                                "category": "Privilege Use",
                                "subcategory": "Sensitive Privilege Use / Non Sensitive Privilege Use",
                                "message_summary": "An operation was attempted on a privileged object.",
                                "field_count": 12,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "ObjectServer",
                                "ObjectType",
                                "ObjectName",
                                "HandleId",
                                "AccessMask",
                                "PrivilegeList",
                                "ProcessId",
                                "ProcessName"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4674"
                            },
                            {
                                "event_id": 4675,
                                "category": "Logon/Logoff",
                                "subcategory": "Logon",
                                "message_summary": "SIDs were filtered.",
                                "field_count": 8,
                                "field_names": [
                                "TargetUserSid",
                                "TargetUserName",
                                "TargetDomainName",
                                "TdoDirection",
                                "TdoAttributes",
                                "TdoType",
                                "TdoSid",
                                "SidList"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4675"
                            },
                            {
                                "event_id": 4688,
                                "category": "Detailed Tracking",
                                "subcategory": "Process Creation",
                                "message_summary": "A new process has been created.",
                                "field_count": 8,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "NewProcessId",
                                "NewProcessName",
                                "CommandLine",
                                "TokenElevationType",
                                "ProcessId"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688"
                            },
                            {
                                "event_id": 4689,
                                "category": "Detailed Tracking",
                                "subcategory": "Process Termination",
                                "message_summary": "A process has exited.",
                                "field_count": 7,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "Status",
                                "ProcessId",
                                "ProcessName"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4689"
                            },
                            {
                                "event_id": 4690,
                                "category": "Object Access",
                                "subcategory": "Handle Manipulation",
                                "message_summary": "An attempt was made to duplicate a handle to an object.",
                                "field_count": 8,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "SourceHandleId",
                                "SourceProcessId",
                                "TargetHandleId",
                                "TargetProcessId"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4690"
                            },
                            {
                                "event_id": 4691,
                                "category": "Object Access",
                                "subcategory": "Other Object Access Events",
                                "message_summary": "Indirect access to an object was requested.",
                                "field_count": 9,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "ObjectType",
                                "ObjectName",
                                "AccessList",
                                "AccessMask",
                                "ProcessId"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4691"
                            },
                            {
                                "event_id": 4692,
                                "category": "Detailed Tracking",
                                "subcategory": "DPAPI Activity",
                                "message_summary": "Backup of data protection master key was attempted.",
                                "field_count": 8,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "MasterKeyId",
                                "RecoveryServer",
                                "RecoveryKeyId",
                                "FailureReason"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4692"
                            },
                            {
                                "event_id": 4693,
                                "category": "Detailed Tracking",
                                "subcategory": "DPAPI Activity",
                                "message_summary": "Recovery of data protection master key was attempted.",
                                "field_count": 9,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "MasterKeyId",
                                "RecoveryReason",
                                "RecoveryServer",
                                "RecoveryKeyId",
                                "FailureId"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4693"
                            },
                            {
                                "event_id": 4694,
                                "category": "Detailed Tracking",
                                "subcategory": "DPAPI Activity",
                                "message_summary": "Protection of auditable protected data was attempted.",
                                "field_count": 9,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "DataDescription",
                                "MasterKeyId",
                                "ProtectedDataFlags",
                                "CryptoAlgorithms",
                                "FailureReason"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4694"
                            },
                            {
                                "event_id": 4696,
                                "category": "Detailed Tracking",
                                "subcategory": "Process Creation",
                                "message_summary": "A primary token was assigned to process.",
                                "field_count": 12,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "TargetUserSid",
                                "TargetUserName",
                                "TargetDomainName",
                                "TargetLogonId",
                                "TargetProcessId",
                                "TargetProcessName",
                                "ProcessId",
                                "ProcessName"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4696"
                            },
                            {
                                "event_id": 4697,
                                "category": "System",
                                "subcategory": "Security System Extension",
                                "message_summary": "A service was installed in the system.",
                                "field_count": 9,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "ServiceName",
                                "ServiceFileName",
                                "ServiceType",
                                "ServiceStartType",
                                "ServiceAccount"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4697"
                            },
                            {
                                "event_id": 4698,
                                "category": "Object Access",
                                "subcategory": "Other Object Access Events",
                                "message_summary": "A scheduled task was created.",
                                "field_count": 6,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "TaskName",
                                "TaskContent"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4698"
                            },
                            {
                                "event_id": 4702,
                                "category": "Object Access",
                                "subcategory": "Other Object Access Events",
                                "message_summary": "A scheduled task was updated.",
                                "field_count": 6,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "TaskName",
                                "TaskContentNew"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4702"
                            },
                            {
                                "event_id": 4704,
                                "category": "Policy Change",
                                "subcategory": "Authorization Policy Change",
                                "message_summary": "A user right was assigned.",
                                "field_count": 6,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "TargetSid",
                                "PrivilegeList"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4704"
                            },
                            {
                                "event_id": 4706,
                                "category": "Policy Change",
                                "subcategory": "Authorization Policy Change",
                                "message_summary": "A new trust was created to a domain.",
                                "field_count": 10,
                                "field_names": [
                                "DomainName",
                                "DomainSid",
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "TdoType",
                                "TdoDirection",
                                "TdoAttributes",
                                "SidFilteringEnabled"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4706"
                            },
                            {
                                "event_id": 4707,
                                "category": "Policy Change",
                                "subcategory": "Authorization Policy Change",
                                "message_summary": "A trust to a domain was removed.",
                                "field_count": 6,
                                "field_names": [
                                "DomainName",
                                "DomainSid",
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4707"
                            },
                            {
                                "event_id": 4709,
                                "category": "Policy Change",
                                "subcategory": "Filtering Platform Policy Change",
                                "message_summary": "IPsec Services was started.",
                                "field_count": 3,
                                "field_names": [
                                "param1",
                                "param2",
                                "param3"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4709"
                            },
                            {
                                "event_id": 4710,
                                "category": "Policy Change",
                                "subcategory": "Filtering Platform Policy Change",
                                "message_summary": "IPsec Services was disabled.",
                                "field_count": 2,
                                "field_names": [
                                "param1",
                                "param2"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4710"
                            },
                            {
                                "event_id": 4711,
                                "category": "Policy Change",
                                "subcategory": "Filtering Platform Policy Change",
                                "message_summary": "May contain any one of the following: PAStore Engine applied locally cached copy of Active Directory storage IPsec policy on the computer.\nPAStore Engine applied Active Directory storage IPsec policy on the computer.\nPAStore Engine applied local registry storage IPsec policy on the computer.\nPAStore Engine failed to apply locally cached copy of Active Directory storage IPsec policy on the computer.\nPAStore Engine failed to apply Active Directory storage IPsec policy on the computer.\nPAStore Engine failed to apply local registry storage IPsec policy on the computer.\nPAStore Engine failed to apply some rules of the active IPsec policy on the computer.\nPAStore Engine failed to load directory storage IPsec policy on the computer.\nPAStore Engine loaded directory storage IPsec policy on the computer.\nPAStore Engine failed to load local storage IPsec policy on the computer.\nPAStore Engine loaded local storage IPsec policy on the computer.\nPAStore Engine polled for changes to the active IPsec policy and detected no changes.",
                                "field_count": 1,
                                "field_names": [
                                "param1"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4711"
                            },
                            {
                                "event_id": 4713,
                                "category": "Policy Change",
                                "subcategory": "Authentication Policy Change",
                                "message_summary": "Kerberos policy was changed.",
                                "field_count": 5,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "KerberosPolicyChange"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4713"
                            },
                            {
                                "event_id": 4714,
                                "category": "Policy Change",
                                "subcategory": "Authorization Policy Change",
                                "message_summary": "Encrypted data recovery policy was changed.",
                                "field_count": 5,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "EfsPolicyChange"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4714"
                            },
                            {
                                "event_id": 4715,
                                "category": "Policy Change",
                                "subcategory": "Audit Policy Change",
                                "message_summary": "The audit policy (SACL) on an object was changed.",
                                "field_count": 6,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "OldSd",
                                "NewSd"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4715"
                            },
                            {
                                "event_id": 4716,
                                "category": "Policy Change",
                                "subcategory": "Authentication Policy Change",
                                "message_summary": "Trusted domain information was modified.",
                                "field_count": 10,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "DomainName",
                                "DomainSid",
                                "TdoType",
                                "TdoDirection",
                                "TdoAttributes",
                                "SidFilteringEnabled"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4716"
                            },
                            {
                                "event_id": 4717,
                                "category": "Policy Change",
                                "subcategory": "Authentication Policy Change",
                                "message_summary": "System security access was granted to an account.",
                                "field_count": 6,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "TargetSid",
                                "AccessGranted"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4717"
                            },
                            {
                                "event_id": 4718,
                                "category": "Policy Change",
                                "subcategory": "Authentication Policy Change",
                                "message_summary": "System security access was removed from an account.",
                                "field_count": 6,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "TargetSid",
                                "AccessRemoved"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4718"
                            },
                            {
                                "event_id": 4719,
                                "category": "Policy Change",
                                "subcategory": "Audit Policy Change",
                                "message_summary": "System audit policy was changed.",
                                "field_count": 8,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "CategoryId",
                                "SubcategoryId",
                                "SubcategoryGuid",
                                "AuditPolicyChanges"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4719"
                            },
                            {
                                "event_id": 4720,
                                "category": "Account Management",
                                "subcategory": "User Account Management",
                                "message_summary": "A user account was created.",
                                "field_count": 26,
                                "field_names": [
                                "TargetUserName",
                                "TargetDomainName",
                                "TargetSid",
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "PrivilegeList",
                                "SamAccountName",
                                "DisplayName",
                                "UserPrincipalName",
                                "HomeDirectory",
                                "HomePath",
                                "ScriptPath",
                                "ProfilePath",
                                "UserWorkstations",
                                "PasswordLastSet",
                                "AccountExpires",
                                "PrimaryGroupId",
                                "AllowedToDelegateTo",
                                "OldUacValue",
                                "NewUacValue",
                                "UserAccountControl",
                                "UserParameters",
                                "SidHistory",
                                "LogonHours"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4720"
                            },
                            {
                                "event_id": 4722,
                                "category": "Account Management",
                                "subcategory": "User Account Management",
                                "message_summary": "A user account was enabled.",
                                "field_count": 7,
                                "field_names": [
                                "TargetUserName",
                                "TargetDomainName",
                                "TargetSid",
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4722"
                            },
                            {
                                "event_id": 4723,
                                "category": "Account Management",
                                "subcategory": "User Account Management",
                                "message_summary": "An attempt was made to change an account's password.",
                                "field_count": 8,
                                "field_names": [
                                "TargetUserName",
                                "TargetDomainName",
                                "TargetSid",
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "PrivilegeList"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4723"
                            },
                            {
                                "event_id": 4727,
                                "category": "Account Management",
                                "subcategory": "Security Group Management",
                                "message_summary": "A security-enabled global group was created.",
                                "field_count": 10,
                                "field_names": [
                                "TargetUserName",
                                "TargetDomainName",
                                "TargetSid",
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "PrivilegeList",
                                "SamAccountName",
                                "SidHistory"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4727"
                            },
                            {
                                "event_id": 4728,
                                "category": "Account Management",
                                "subcategory": "Security Group Management",
                                "message_summary": "A member was added to a security-enabled global group.",
                                "field_count": 10,
                                "field_names": [
                                "MemberName",
                                "MemberSid",
                                "TargetUserName",
                                "TargetDomainName",
                                "TargetSid",
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "PrivilegeList"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4728"
                            },
                            {
                                "event_id": 4738,
                                "category": "Account Management",
                                "subcategory": "User Account Management",
                                "message_summary": "A user account was changed.",
                                "field_count": 27,
                                "field_names": [
                                "Dummy",
                                "TargetUserName",
                                "TargetDomainName",
                                "TargetSid",
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "PrivilegeList",
                                "SamAccountName",
                                "DisplayName",
                                "UserPrincipalName",
                                "HomeDirectory",
                                "HomePath",
                                "ScriptPath",
                                "ProfilePath",
                                "UserWorkstations",
                                "PasswordLastSet",
                                "AccountExpires",
                                "PrimaryGroupId",
                                "AllowedToDelegateTo",
                                "OldUacValue",
                                "NewUacValue",
                                "UserAccountControl",
                                "UserParameters",
                                "SidHistory",
                                "LogonHours"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4738"
                            },
                            {
                                "event_id": 4739,
                                "category": "Policy Change",
                                "subcategory": "Authentication Policy Change",
                                "message_summary": "Domain Policy was changed.",
                                "field_count": 21,
                                "field_names": [
                                "DomainPolicyChanged",
                                "DomainName",
                                "DomainSid",
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "PrivilegeList",
                                "MinPasswordAge",
                                "MaxPasswordAge",
                                "ForceLogoff",
                                "LockoutThreshold",
                                "LockoutObservationWindow",
                                "LockoutDuration",
                                "PasswordProperties",
                                "MinPasswordLength",
                                "PasswordHistoryLength",
                                "MachineAccountQuota",
                                "MixedDomainMode",
                                "DomainBehaviorVersion",
                                "OemInformation"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4739"
                            },
                            {
                                "event_id": 4742,
                                "category": "Account Management",
                                "subcategory": "Computer Account Management",
                                "message_summary": "A computer account was changed.",
                                "field_count": 29,
                                "field_names": [
                                "ComputerAccountChange",
                                "TargetUserName",
                                "TargetDomainName",
                                "TargetSid",
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "PrivilegeList",
                                "SamAccountName",
                                "DisplayName",
                                "UserPrincipalName",
                                "HomeDirectory",
                                "HomePath",
                                "ScriptPath",
                                "ProfilePath",
                                "UserWorkstations",
                                "PasswordLastSet",
                                "AccountExpires",
                                "PrimaryGroupId",
                                "AllowedToDelegateTo",
                                "OldUacValue",
                                "NewUacValue",
                                "UserAccountControl",
                                "UserParameters",
                                "SidHistory",
                                "LogonHours",
                                "DnsHostName",
                                "ServicePrincipalNames"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4742"
                            },
                            {
                                "event_id": 4764,
                                "category": "Account Management",
                                "subcategory": "Security Group Management",
                                "message_summary": "A group’s type was changed.",
                                "field_count": 9,
                                "field_names": [
                                "GroupTypeChange",
                                "TargetUserName",
                                "TargetDomainName",
                                "TargetSid",
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "PrivilegeList"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4764"
                            },
                            {
                                "event_id": 4765,
                                "category": "Account Management",
                                "subcategory": "User Account Management",
                                "message_summary": "SID History was added to an account.",
                                "field_count": 11,
                                "field_names": [
                                "SourceUserName",
                                "SourceSid",
                                "TargetUserName",
                                "TargetDomainName",
                                "TargetSid",
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "PrivilegeList",
                                "SidList"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4765"
                            },
                            {
                                "event_id": 4766,
                                "category": "Account Management",
                                "subcategory": "User Account Management",
                                "message_summary": "An attempt to add SID History to an account failed.",
                                "field_count": 8,
                                "field_names": [
                                "SourceUserName",
                                "TargetUserName",
                                "TargetDomainName",
                                "TargetSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "PrivilegeList"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4766"
                            },
                            {
                                "event_id": 4768,
                                "category": "Account Logon",
                                "subcategory": "Kerberos Authentication Service",
                                "message_summary": "A Kerberos authentication ticket (TGT) was requested.",
                                "field_count": 14,
                                "field_names": [
                                "TargetUserName",
                                "TargetDomainName",
                                "TargetSid",
                                "ServiceName",
                                "ServiceSid",
                                "TicketOptions",
                                "Status",
                                "TicketEncryptionType",
                                "PreAuthType",
                                "IpAddress",
                                "IpPort",
                                "CertIssuerName",
                                "CertSerialNumber",
                                "CertThumbprint"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768"
                            },
                            {
                                "event_id": 4769,
                                "category": "Account Logon",
                                "subcategory": "Kerberos Service Ticket Operations",
                                "message_summary": "A Kerberos service ticket was requested.",
                                "field_count": 11,
                                "field_names": [
                                "TargetUserName",
                                "TargetDomainName",
                                "ServiceName",
                                "ServiceSid",
                                "TicketOptions",
                                "TicketEncryptionType",
                                "IpAddress",
                                "IpPort",
                                "Status",
                                "LogonGuid",
                                "TransmittedServices"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769"
                            },
                            {
                                "event_id": 4770,
                                "category": "Account Logon",
                                "subcategory": "Kerberos Service Ticket Operations",
                                "message_summary": "A Kerberos service ticket was renewed.",
                                "field_count": 8,
                                "field_names": [
                                "TargetUserName",
                                "TargetDomainName",
                                "ServiceName",
                                "ServiceSid",
                                "TicketOptions",
                                "TicketEncryptionType",
                                "IpAddress",
                                "IpPort"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4770"
                            },
                            {
                                "event_id": 4771,
                                "category": "Account Logon",
                                "subcategory": "Kerberos Authentication Service",
                                "message_summary": "Kerberos pre-authentication failed.",
                                "field_count": 11,
                                "field_names": [
                                "TargetUserName",
                                "TargetSid",
                                "ServiceName",
                                "TicketOptions",
                                "Status",
                                "PreAuthType",
                                "IpAddress",
                                "IpPort",
                                "CertIssuerName",
                                "CertSerialNumber",
                                "CertThumbprint"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4771"
                            },
                            {
                                "event_id": 4772,
                                "category": "Account Logon",
                                "subcategory": "Kerberos Authentication Service",
                                "message_summary": "A Kerberos authentication ticket request failed.",
                                "field_count": 7,
                                "field_names": [
                                "TargetUserName",
                                "TargetDomainName",
                                "ServiceName",
                                "TicketOptions",
                                "FailureCode",
                                "IpAddress",
                                "IpPort"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4772"
                            },
                            {
                                "event_id": 4774,
                                "category": "Account Logon",
                                "subcategory": "Credential Validation",
                                "message_summary": "An account was mapped for logon.",
                                "field_count": 3,
                                "field_names": [
                                "MappingBy",
                                "ClientUserName",
                                "MappedName"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4774"
                            },
                            {
                                "event_id": 4775,
                                "category": "Account Logon",
                                "subcategory": "Credential Validation",
                                "message_summary": "An account could not be mapped for logon.",
                                "field_count": 2,
                                "field_names": [
                                "ClientUserName",
                                "MappingBy"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4775"
                            },
                            {
                                "event_id": 4776,
                                "category": "Account Logon",
                                "subcategory": "Credential Validation",
                                "message_summary": "The domain controller attempted to validate the credentials for an account.",
                                "field_count": 4,
                                "field_names": [
                                "PackageName",
                                "TargetUserName",
                                "Workstation",
                                "Status"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4776"
                            },
                            {
                                "event_id": 4777,
                                "category": "Account Logon",
                                "subcategory": "Credential Validation",
                                "message_summary": "The domain controller failed to validate the credentials for an account.",
                                "field_count": 4,
                                "field_names": [
                                "ClientUserName",
                                "TargetUserName",
                                "Workstation",
                                "Status"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4777"
                            },
                            {
                                "event_id": 4778,
                                "category": "Logon/Logoff",
                                "subcategory": "Other Logon/Logoff Events",
                                "message_summary": "A session was reconnected to a Window Station.",
                                "field_count": 6,
                                "field_names": [
                                "AccountName",
                                "AccountDomain",
                                "LogonID",
                                "SessionName",
                                "ClientName",
                                "ClientAddress"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4778"
                            },
                            {
                                "event_id": 4781,
                                "category": "Account Management",
                                "subcategory": "User Account Management",
                                "message_summary": "The name of an account was changed:",
                                "field_count": 9,
                                "field_names": [
                                "OldTargetUserName",
                                "NewTargetUserName",
                                "TargetDomainName",
                                "TargetSid",
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "PrivilegeList"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4781"
                            },
                            {
                                "event_id": 4782,
                                "category": "Account Management",
                                "subcategory": "Other Account Management Events",
                                "message_summary": "The password hash an account was accessed.",
                                "field_count": 6,
                                "field_names": [
                                "TargetUserName",
                                "TargetDomainName",
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4782"
                            },
                            {
                                "event_id": 4793,
                                "category": "Account Management",
                                "subcategory": "Other Account Management Events",
                                "message_summary": "The Password Policy Checking API was called.",
                                "field_count": 7,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "Workstation",
                                "TargetUserName",
                                "Status"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4793"
                            },
                            {
                                "event_id": 4794,
                                "category": "Account Management",
                                "subcategory": "User Account Management",
                                "message_summary": "An attempt was made to set the Directory Services Restore Mode.",
                                "field_count": 6,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "Workstation",
                                "Status"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4794"
                            },
                            {
                                "event_id": 4800,
                                "category": "Logon/Logoff",
                                "subcategory": "Other Logon/Logoff Events",
                                "message_summary": "The workstation was locked.",
                                "field_count": 5,
                                "field_names": [
                                "TargetUserSid",
                                "TargetUserName",
                                "TargetDomainName",
                                "TargetLogonId",
                                "SessionId"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4800"
                            },
                            {
                                "event_id": 4816,
                                "category": "System",
                                "subcategory": "System Integrity",
                                "message_summary": "RPC detected an integrity violation while decrypting an incoming message.",
                                "field_count": 3,
                                "field_names": [
                                "PeerName",
                                "ProtocolSequence",
                                "SecurityError"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4816"
                            },
                            {
                                "event_id": 4817,
                                "category": "Policy Change",
                                "subcategory": "Audit Policy Change",
                                "message_summary": "Auditing settings on an object were changed.",
                                "field_count": 9,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "ObjectServer",
                                "ObjectType",
                                "ObjectName",
                                "OldSd",
                                "NewSd"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4817"
                            },
                            {
                                "event_id": 4864,
                                "category": "Policy Change",
                                "subcategory": "Authentication Policy Change",
                                "message_summary": "A namespace collision was detected.",
                                "field_count": 8,
                                "field_names": [
                                "CollisionTargetType",
                                "CollisionTargetName",
                                "ForestRoot",
                                "TopLevelName",
                                "DnsName",
                                "NetbiosName",
                                "DomainSid",
                                "Flags"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4864"
                            },
                            {
                                "event_id": 4865,
                                "category": "Policy Change",
                                "subcategory": "Authentication Policy Change",
                                "message_summary": "A trusted forest information entry was added.",
                                "field_count": 13,
                                "field_names": [
                                "ForestRoot",
                                "ForestRootSid",
                                "OperationId",
                                "EntryType",
                                "Flags",
                                "TopLevelName",
                                "DnsName",
                                "NetbiosName",
                                "DomainSid",
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4865"
                            },
                            {
                                "event_id": 4867,
                                "category": "Policy Change",
                                "subcategory": "Authentication Policy Change",
                                "message_summary": "A trusted forest information entry was modified.",
                                "field_count": 13,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "ForestRoot",
                                "ForestRootSid",
                                "OperationId",
                                "EntryType",
                                "Flags",
                                "TopLevelName",
                                "DnsName",
                                "NetbiosName",
                                "DomainSid"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4867"
                            },
                            {
                                "event_id": 4868,
                                "category": "Object Access",
                                "subcategory": "Certification Services",
                                "message_summary": "The certificate manager denied a pending certificate request.",
                                "field_count": 5,
                                "field_names": [
                                "RequestId",
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4868"
                            },
                            {
                                "event_id": 4870,
                                "category": "Object Access",
                                "subcategory": "Certification Services",
                                "message_summary": "Certificate Services revoked a certificate.",
                                "field_count": 6,
                                "field_names": [
                                "CertificateSerialNumber",
                                "RevocationReason",
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4870"
                            },
                            {
                                "event_id": 4871,
                                "category": "Object Access",
                                "subcategory": "Certification Services",
                                "message_summary": "Certificate Services received a request to publish the certificate revocation list (CRL).",
                                "field_count": 7,
                                "field_names": [
                                "NextUpdate",
                                "NextPublishForBaseCRL",
                                "NextPublishForDeltaCRL",
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4871"
                            },
                            {
                                "event_id": 4872,
                                "category": "Object Access",
                                "subcategory": "Certification Services",
                                "message_summary": "Certificate Services published the certificate revocation list (CRL).",
                                "field_count": 5,
                                "field_names": [
                                "IsBaseCRL",
                                "CRLNumber",
                                "KeyContainer",
                                "NextPublish",
                                "PublishURLs"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4872"
                            },
                            {
                                "event_id": 4873,
                                "category": "Object Access",
                                "subcategory": "Certification Services",
                                "message_summary": "A certificate request extension changed.",
                                "field_count": 9,
                                "field_names": [
                                "RequestId",
                                "ExtensionName",
                                "ExtensionDataType",
                                "ExtensionPolicyFlags",
                                "ExtensionData",
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4873"
                            },
                            {
                                "event_id": 4874,
                                "category": "Object Access",
                                "subcategory": "Certification Services",
                                "message_summary": "One or more certificate request attributes changed.",
                                "field_count": 6,
                                "field_names": [
                                "RequestId",
                                "Attributes",
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4874"
                            },
                            {
                                "event_id": 4875,
                                "category": "Object Access",
                                "subcategory": "Certification Services",
                                "message_summary": "Certificate Services received a request to shut down.",
                                "field_count": 4,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4875"
                            },
                            {
                                "event_id": 4876,
                                "category": "Object Access",
                                "subcategory": "Certification Services",
                                "message_summary": "Certificate Services backup started.",
                                "field_count": 5,
                                "field_names": [
                                "BackupType",
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4876"
                            },
                            {
                                "event_id": 4880,
                                "category": "Object Access",
                                "subcategory": "Certification Services",
                                "message_summary": "Certificate Services started.",
                                "field_count": 4,
                                "field_names": [
                                "CertificateDatabaseHash",
                                "PrivateKeyUsageCount",
                                "CACertificateHash",
                                "CAPublicKeyHash"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4880"
                            },
                            {
                                "event_id": 4882,
                                "category": "Object Access",
                                "subcategory": "Certification Services",
                                "message_summary": "The security permissions for Certificate Services changed.",
                                "field_count": 5,
                                "field_names": [
                                "SecuritySettings",
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4882"
                            },
                            {
                                "event_id": 4884,
                                "category": "Object Access",
                                "subcategory": "Certification Services",
                                "message_summary": "Certificate Services imported a certificate into its database.",
                                "field_count": 6,
                                "field_names": [
                                "Certificate",
                                "RequestId",
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4884"
                            },
                            {
                                "event_id": 4885,
                                "category": "Object Access",
                                "subcategory": "Certification Services",
                                "message_summary": "The audit filter for Certificate Services changed.",
                                "field_count": 5,
                                "field_names": [
                                "AuditFilter",
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4885"
                            },
                            {
                                "event_id": 4886,
                                "category": "Object Access",
                                "subcategory": "Certification Services",
                                "message_summary": "Certificate Services received a certificate request.",
                                "field_count": 3,
                                "field_names": [
                                "RequestId",
                                "Requester",
                                "Attributes"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4886"
                            },
                            {
                                "event_id": 4887,
                                "category": "Object Access",
                                "subcategory": "Certification Services",
                                "message_summary": "Certificate Services approved a certificate request and issued a certificate.",
                                "field_count": 6,
                                "field_names": [
                                "RequestId",
                                "Requester",
                                "Attributes",
                                "Disposition",
                                "SubjectKeyIdentifier",
                                "Subject"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4887"
                            },
                            {
                                "event_id": 4890,
                                "category": "Object Access",
                                "subcategory": "Certification Services",
                                "message_summary": "The certificate manager settings for Certificate Services changed.",
                                "field_count": 6,
                                "field_names": [
                                "EnableRestrictedPermissions",
                                "RestrictedPermissions",
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4890"
                            },
                            {
                                "event_id": 4891,
                                "category": "Object Access",
                                "subcategory": "Certification Services",
                                "message_summary": "A configuration entry changed in Certificate Services.",
                                "field_count": 7,
                                "field_names": [
                                "Node",
                                "Entry",
                                "Value",
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4891"
                            },
                            {
                                "event_id": 4892,
                                "category": "Object Access",
                                "subcategory": "Certification Services",
                                "message_summary": "A property of Certificate Services changed.",
                                "field_count": 8,
                                "field_names": [
                                "PropertyName",
                                "PropertyIndex",
                                "PropertyType",
                                "PropertyValue",
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4892"
                            },
                            {
                                "event_id": 4893,
                                "category": "Object Access",
                                "subcategory": "Certification Services",
                                "message_summary": "Certificate Services archived a key.",
                                "field_count": 3,
                                "field_names": [
                                "RequestId",
                                "Requester",
                                "KRAHashes"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4893"
                            },
                            {
                                "event_id": 4895,
                                "category": "Object Access",
                                "subcategory": "Certification Services",
                                "message_summary": "Certificate Services published the CA certificate to Active Directory Domain Services.",
                                "field_count": 3,
                                "field_names": [
                                "CertificateHash",
                                "ValidFrom",
                                "ValidTo"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4895"
                            },
                            {
                                "event_id": 4896,
                                "category": "Object Access",
                                "subcategory": "Certification Services",
                                "message_summary": "One or more rows have been deleted from the certificate database.",
                                "field_count": 7,
                                "field_names": [
                                "TableId",
                                "Filter",
                                "RowsDeleted",
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4896"
                            },
                            {
                                "event_id": 4897,
                                "category": "Object Access",
                                "subcategory": "Certification Services",
                                "message_summary": "Role separation enabled:",
                                "field_count": 1,
                                "field_names": [
                                "RoleSeparationEnabled"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4897"
                            },
                            {
                                "event_id": 4898,
                                "category": "Object Access",
                                "subcategory": "Certification Services",
                                "message_summary": "Certificate Services loaded a template.",
                                "field_count": 8,
                                "field_names": [
                                "TemplateInternalName",
                                "TemplateVersion",
                                "TemplateSchemaVersion",
                                "TemplateOID",
                                "TemplateDSObjectFQDN",
                                "DCDNSName",
                                "TemplateContent",
                                "SecurityDescriptor"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4898"
                            },
                            {
                                "event_id": 4899,
                                "category": "Object Access",
                                "subcategory": "Certification Services",
                                "message_summary": "A Certificate Services template was updated.",
                                "field_count": 8,
                                "field_names": [
                                "TemplateInternalName",
                                "TemplateVersion",
                                "TemplateSchemaVersion",
                                "TemplateOID",
                                "TemplateDSObjectFQDN",
                                "DCDNSName",
                                "NewTemplateContent",
                                "OldTemplateContent"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4899"
                            },
                            {
                                "event_id": 4900,
                                "category": "Object Access",
                                "subcategory": "Certification Services",
                                "message_summary": "Certificate Services template security was updated.",
                                "field_count": 10,
                                "field_names": [
                                "TemplateInternalName",
                                "TemplateVersion",
                                "TemplateSchemaVersion",
                                "TemplateOID",
                                "TemplateDSObjectFQDN",
                                "DCDNSName",
                                "NewTemplateContent",
                                "NewSecurityDescriptor",
                                "OldTemplateContent",
                                "OldSecurityDescriptor"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4900"
                            },
                            {
                                "event_id": 4902,
                                "category": "Policy Change",
                                "subcategory": "Audit Policy Change",
                                "message_summary": "The Per-user audit policy table was created.",
                                "field_count": 2,
                                "field_names": [
                                "PuaCount",
                                "PuaPolicyId"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4902"
                            },
                            {
                                "event_id": 4904,
                                "category": "Policy Change",
                                "subcategory": "Audit Policy Change",
                                "message_summary": "An attempt was made to register a security event source.",
                                "field_count": 8,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "AuditSourceName",
                                "EventSourceId",
                                "ProcessId",
                                "ProcessName"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4904"
                            },
                            {
                                "event_id": 4906,
                                "category": "Policy Change",
                                "subcategory": "Audit Policy Change",
                                "message_summary": "The CrashOnAuditFail value has changed.",
                                "field_count": 1,
                                "field_names": [
                                "CrashOnAuditFailValue"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4906"
                            },
                            {
                                "event_id": 4908,
                                "category": "Policy Change",
                                "subcategory": "Audit Policy Change",
                                "message_summary": "Special Groups Logon table modified.",
                                "field_count": 1,
                                "field_names": [
                                "SidList"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4908"
                            },
                            {
                                "event_id": 4909,
                                "category": "Policy Change",
                                "subcategory": "Other Policy Change Events",
                                "message_summary": "The local policy settings for the TBS were changed.",
                                "field_count": 2,
                                "field_names": [
                                "OldBlockedOrdinals",
                                "NewBlockedOrdinals"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4909"
                            },
                            {
                                "event_id": 4910,
                                "category": "Policy Change",
                                "subcategory": "Other Policy Change Events",
                                "message_summary": "The group policy settings for the TBS were changed.",
                                "field_count": 6,
                                "field_names": [
                                "OldIgnoreDefaultSettings",
                                "NewIgnoreDefaultSettings",
                                "OldIgnoreLocalSettings",
                                "NewIgnoreLocalSettings",
                                "OldBlockedOrdinals",
                                "NewBlockedOrdinals"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4910"
                            },
                            {
                                "event_id": 4912,
                                "category": "Policy Change",
                                "subcategory": "Audit Policy Change",
                                "message_summary": "Per User Audit Policy was changed.",
                                "field_count": 9,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "TargetUserSid",
                                "CategoryId",
                                "SubcategoryId",
                                "SubcategoryGuid",
                                "AuditPolicyChanges"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4912"
                            },
                            {
                                "event_id": 4928,
                                "category": "DS Access",
                                "subcategory": "Detailed Directory Service Replication",
                                "message_summary": "An Active Directory replica source naming context was established.",
                                "field_count": 6,
                                "field_names": [
                                "DestinationDRA",
                                "SourceDRA",
                                "SourceAddr",
                                "NamingContext",
                                "Options",
                                "StatusCode"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4928"
                            },
                            {
                                "event_id": 4932,
                                "category": "DS Access",
                                "subcategory": "Directory Service Replication",
                                "message_summary": "Synchronization of a replica of an Active Directory naming context has begun.",
                                "field_count": 6,
                                "field_names": [
                                "DestinationDRA",
                                "SourceDRA",
                                "NamingContext",
                                "Options",
                                "SessionID",
                                "StartUSN"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4932"
                            },
                            {
                                "event_id": 4933,
                                "category": "DS Access",
                                "subcategory": "Directory Service Replication",
                                "message_summary": "Synchronization of a replica of an Active Directory naming context has ended.",
                                "field_count": 7,
                                "field_names": [
                                "DestinationDRA",
                                "SourceDRA",
                                "NamingContext",
                                "Options",
                                "SessionID",
                                "EndUSN",
                                "StatusCode"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4933"
                            },
                            {
                                "event_id": 4934,
                                "category": "DS Access",
                                "subcategory": "Detailed Directory Service Replication",
                                "message_summary": "Attributes of an Active Directory object were replicated.",
                                "field_count": 7,
                                "field_names": [
                                "SessionID",
                                "Object",
                                "Attribute",
                                "TypeOfChange",
                                "NewValue",
                                "USN",
                                "StatusCode"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4934"
                            },
                            {
                                "event_id": 4935,
                                "category": "DS Access",
                                "subcategory": "Detailed Directory Service Replication",
                                "message_summary": "Replication failure begins.",
                                "field_count": 2,
                                "field_names": [
                                "ReplicationEvent",
                                "AuditStatusCode"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4935"
                            },
                            {
                                "event_id": 4936,
                                "category": "DS Access",
                                "subcategory": "Detailed Directory Service Replication",
                                "message_summary": "Replication failure ends.",
                                "field_count": 3,
                                "field_names": [
                                "ReplicationEvent",
                                "AuditStatusCode",
                                "ReplicationStatusCode"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4936"
                            },
                            {
                                "event_id": 4937,
                                "category": "DS Access",
                                "subcategory": "Detailed Directory Service Replication",
                                "message_summary": "A lingering object was removed from a replica.",
                                "field_count": 5,
                                "field_names": [
                                "DestinationDRA",
                                "SourceDRA",
                                "Object",
                                "Options",
                                "StatusCode"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4937"
                            },
                            {
                                "event_id": 4944,
                                "category": "Policy Change",
                                "subcategory": "MPSSVC Rule-Level Policy Change",
                                "message_summary": "The following policy was active when the Windows Firewall started.",
                                "field_count": 7,
                                "field_names": [
                                "GroupPolicyApplied",
                                "Profile",
                                "OperationMode",
                                "RemoteAdminEnabled",
                                "MulticastFlowsEnabled",
                                "LogDroppedPacketsEnabled",
                                "LogSuccessfulConnectionsEnabled"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4944"
                            },
                            {
                                "event_id": 4945,
                                "category": "Policy Change",
                                "subcategory": "MPSSVC Rule-Level Policy Change",
                                "message_summary": "A rule was listed when the Windows Firewall started.",
                                "field_count": 3,
                                "field_names": [
                                "ProfileUsed",
                                "RuleId",
                                "RuleName"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4945"
                            },
                            {
                                "event_id": 4946,
                                "category": "Policy Change",
                                "subcategory": "MPSSVC Rule-Level Policy Change",
                                "message_summary": "A change has been made to Windows Firewall exception list. A rule was added.",
                                "field_count": 3,
                                "field_names": [
                                "ProfileChanged",
                                "RuleId",
                                "RuleName"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4946"
                            },
                            {
                                "event_id": 4950,
                                "category": "Policy Change",
                                "subcategory": "MPSSVC Rule-Level Policy Change",
                                "message_summary": "A Windows Firewall setting has changed.",
                                "field_count": 3,
                                "field_names": [
                                "ProfileChanged",
                                "SettingType",
                                "SettingValue"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4950"
                            },
                            {
                                "event_id": 4951,
                                "category": "Policy Change",
                                "subcategory": "MPSSVC Rule-Level Policy Change",
                                "message_summary": "A rule has been ignored because its major version number was not recognized by Windows Firewall.",
                                "field_count": 3,
                                "field_names": [
                                "Profile",
                                "RuleId",
                                "RuleName"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4951"
                            },
                            {
                                "event_id": 4953,
                                "category": "Policy Change",
                                "subcategory": "MPSSVC Rule-Level Policy Change",
                                "message_summary": "A rule has been ignored by Windows Firewall because it could not parse the rule.",
                                "field_count": 4,
                                "field_names": [
                                "Profile",
                                "ReasonForRejection",
                                "RuleId",
                                "RuleName"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4953"
                            },
                            {
                                "event_id": 4956,
                                "category": "Policy Change",
                                "subcategory": "MPSSVC Rule-Level Policy Change",
                                "message_summary": "Windows Firewall has changed the active profile.",
                                "field_count": 1,
                                "field_names": [
                                "ActiveProfile"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4956"
                            },
                            {
                                "event_id": 4957,
                                "category": "Policy Change",
                                "subcategory": "MPSSVC Rule-Level Policy Change",
                                "message_summary": "Windows Firewall did not apply the following rule:",
                                "field_count": 3,
                                "field_names": [
                                "RuleId",
                                "RuleName",
                                "RuleAttr"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4957"
                            },
                            {
                                "event_id": 4958,
                                "category": "Policy Change",
                                "subcategory": "MPSSVC Rule-Level Policy Change",
                                "message_summary": "Windows Firewall did not apply the following rule because the rule referred to items not configured on this computer:",
                                "field_count": 4,
                                "field_names": [
                                "RuleId",
                                "RuleName",
                                "Error",
                                "Reason"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4958"
                            },
                            {
                                "event_id": 4960,
                                "category": "System",
                                "subcategory": "IPsec Driver",
                                "message_summary": "IPsec dropped an inbound packet that failed an integrity check. If this problem persists, it could indicate a network issue or that packets are being modified in transit to this computer. Verify that the packets sent from the remote computer are the same as those received by this computer. This error might also indicate interoperability problems with other IPsec implementations.",
                                "field_count": 2,
                                "field_names": [
                                "RemoteAddress",
                                "SPI"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4960"
                            },
                            {
                                "event_id": 4964,
                                "category": "Logon/Logoff",
                                "subcategory": "Special Logon",
                                "message_summary": "Special groups have been assigned to a new logon.",
                                "field_count": 11,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "LogonGuid",
                                "TargetUserSid",
                                "TargetUserName",
                                "TargetDomainName",
                                "TargetLogonId",
                                "TargetLogonGuid",
                                "SidList"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4964"
                            },
                            {
                                "event_id": 4976,
                                "category": "Logon/Logoff",
                                "subcategory": "IPsec Main Mode",
                                "message_summary": "During Main Mode negotiation, IPsec received an invalid negotiation packet. If this problem persists, it could indicate a network issue or an attempt to modify or replay this negotiation.",
                                "field_count": 3,
                                "field_names": [
                                "LocalAddress",
                                "RemoteAddress",
                                "KeyModName"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4976"
                            },
                            {
                                "event_id": 4979,
                                "category": "Logon/Logoff",
                                "subcategory": "IPsec Extended Mode",
                                "message_summary": "IPsec Main Mode and Extended Mode security associations were established.",
                                "field_count": 21,
                                "field_names": [
                                "LocalMMPrincipalName",
                                "RemoteMMPrincipalName",
                                "LocalAddress",
                                "LocalKeyModPort",
                                "RemoteAddress",
                                "RemoteKeyModPort",
                                "MMAuthMethod",
                                "MMCipherAlg",
                                "MMIntegrityAlg",
                                "DHGroup",
                                "MMLifetime",
                                "QMLimit",
                                "Role",
                                "MMImpersonationState",
                                "MMFilterID",
                                "MMSAID",
                                "LocalEMPrincipalName",
                                "RemoteEMPrincipalName",
                                "EMAuthMethod",
                                "EMImpersonationState",
                                "QMFilterID"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4979"
                            },
                            {
                                "event_id": 4980,
                                "category": "Logon/Logoff",
                                "subcategory": "IPsec Extended Mode",
                                "message_summary": "IPsec Main Mode and Extended Mode security associations were established.",
                                "field_count": 26,
                                "field_names": [
                                "LocalMMPrincipalName",
                                "RemoteMMPrincipalName",
                                "LocalAddress",
                                "LocalKeyModPort",
                                "RemoteAddress",
                                "RemoteKeyModPort",
                                "MMAuthMethod",
                                "MMCipherAlg",
                                "MMIntegrityAlg",
                                "DHGroup",
                                "MMLifetime",
                                "QMLimit",
                                "Role",
                                "MMImpersonationState",
                                "MMFilterID",
                                "MMSAID",
                                "LocalEMPrincipalName",
                                "LocalEMCertHash",
                                "LocalEMIssuingCA",
                                "LocalEMRootCA",
                                "RemoteEMPrincipalName",
                                "RemoteEMCertHash",
                                "RemoteEMIssuingCA",
                                "RemoteEMRootCA",
                                "EMImpersonationState",
                                "QMFilterID"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4980"
                            },
                            {
                                "event_id": 4981,
                                "category": "Logon/Logoff",
                                "subcategory": "IPsec Extended Mode",
                                "message_summary": "IPsec Main Mode and Extended Mode security associations were established.",
                                "field_count": 26,
                                "field_names": [
                                "LocalMMPrincipalName",
                                "LocalMMCertHash",
                                "LocalMMIssuingCA",
                                "LocalMMRootCA",
                                "RemoteMMPrincipalName",
                                "RemoteMMCertHash",
                                "RemoteMMIssuingCA",
                                "RemoteMMRootCA",
                                "LocalAddress",
                                "LocalKeyModPort",
                                "RemoteAddress",
                                "RemoteKeyModPort",
                                "MMCipherAlg",
                                "MMIntegrityAlg",
                                "DHGroup",
                                "MMLifetime",
                                "QMLimit",
                                "Role",
                                "MMImpersonationState",
                                "MMFilterID",
                                "MMSAID",
                                "LocalEMPrincipalName",
                                "RemoteEMPrincipalName",
                                "EMAuthMethod",
                                "EMImpersonationState",
                                "QMFilterID"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4981"
                            },
                            {
                                "event_id": 4982,
                                "category": "Logon/Logoff",
                                "subcategory": "IPsec Extended Mode",
                                "message_summary": "IPsec Main Mode and Extended Mode security associations were established.",
                                "field_count": 30,
                                "field_names": [
                                "LocalMMPrincipalName",
                                "LocalMMCertHash",
                                "LocalMMIssuingCA",
                                "LocalMMRootCA",
                                "RemoteMMPrincipalName",
                                "RemoteMMCertHash",
                                "RemoteMMIssuingCA",
                                "RemoteMMRootCA",
                                "LocalKeyModPort",
                                "RemoteAddress",
                                "RemoteKeyModPort",
                                "MMCipherAlg",
                                "MMIntegrityAlg",
                                "DHGroup",
                                "MMLifetime",
                                "QMLimit",
                                "Role",
                                "MMImpersonationState",
                                "MMFilterID",
                                "MMSAID",
                                "LocalEMPrincipalName",
                                "LocalEMCertHash",
                                "LocalEMIssuingCA",
                                "LocalEMRootCA",
                                "RemoteEMPrincipalName",
                                "RemoteEMCertHash",
                                "RemoteEMIssuingCA",
                                "RemoteEMRootCA",
                                "EMImpersonationState",
                                "QMFilterID"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4982"
                            },
                            {
                                "event_id": 4983,
                                "category": "Logon/Logoff",
                                "subcategory": "IPsec Extended Mode",
                                "message_summary": "An IPsec Extended Mode negotiation failed. The corresponding Main Mode security association has been deleted.",
                                "field_count": 18,
                                "field_names": [
                                "LocalEMPrincipalName",
                                "LocalEMCertHash",
                                "LocalEMIssuingCA",
                                "LocalEMRootCA",
                                "RemoteEMPrincipalName",
                                "RemoteEMCertHash",
                                "RemoteEMIssuingCA",
                                "RemoteEMRootCA",
                                "LocalAddress",
                                "LocalKeyModPort",
                                "RemoteAddress",
                                "RemoteKeyModPort",
                                "FailurePoint",
                                "FailureReason",
                                "State",
                                "Role",
                                "EMImpersonationState",
                                "QMFilterID"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4983"
                            },
                            {
                                "event_id": 4984,
                                "category": "Logon/Logoff",
                                "subcategory": "IPsec Extended Mode",
                                "message_summary": "An IPsec Extended Mode negotiation failed. The corresponding Main Mode security association has been deleted.",
                                "field_count": 13,
                                "field_names": [
                                "LocalEMPrincipalName",
                                "RemoteEMPrincipalName",
                                "LocalAddress",
                                "LocalKeyModPort",
                                "RemoteAddress",
                                "RemoteKeyModPort",
                                "FailurePoint",
                                "FailureReason",
                                "EMAuthMethod",
                                "State",
                                "Role",
                                "EMImpersonationState",
                                "QMFilterID"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4984"
                            },
                            {
                                "event_id": 4985,
                                "category": "Object Access",
                                "subcategory": "File System",
                                "message_summary": "The state of a transaction has changed.",
                                "field_count": 9,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "TransactionId",
                                "NewState",
                                "ResourceManager",
                                "ProcessId",
                                "ProcessName"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4985"
                            },
                            {
                                "event_id": 5027,
                                "category": "System",
                                "subcategory": "Other System Events",
                                "message_summary": "The Windows Firewall Service was unable to retrieve the security policy from the local storage. The service will continue enforcing the current policy.",
                                "field_count": 1,
                                "field_names": [
                                "ErrorCode"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5027"
                            },
                            {
                                "event_id": 5031,
                                "category": "Object Access",
                                "subcategory": "Filtering Platform Connection",
                                "message_summary": "The Windows Firewall Service blocked an application from accepting incoming connections on the network.",
                                "field_count": 2,
                                "field_names": [
                                "Profiles",
                                "Application"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5031"
                            },
                            {
                                "event_id": 5039,
                                "category": "Object Access",
                                "subcategory": "Registry",
                                "message_summary": "A registry key was virtualized.",
                                "field_count": 8,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "ObjectPath",
                                "ObjectVirtualPath",
                                "ProcessId",
                                "ProcessName"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5039"
                            },
                            {
                                "event_id": 5040,
                                "category": "Policy Change",
                                "subcategory": "Filtering Platform Policy Change",
                                "message_summary": "A change has been made to IPsec settings. An Authentication Set was added.",
                                "field_count": 3,
                                "field_names": [
                                "ProfileChanged",
                                "AuthenticationSetId",
                                "AuthenticationSetName"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5040"
                            },
                            {
                                "event_id": 5043,
                                "category": "Policy Change",
                                "subcategory": "Filtering Platform Policy Change",
                                "message_summary": "A change has been made to IPsec settings. A Connection Security Rule was added.",
                                "field_count": 3,
                                "field_names": [
                                "ProfileChanged",
                                "ConnectionSecurityRuleId",
                                "ConnectionSecurityRuleName"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5043"
                            },
                            {
                                "event_id": 5046,
                                "category": "Policy Change",
                                "subcategory": "Filtering Platform Policy Change",
                                "message_summary": "A change has been made to IPsec settings. A Crypto Set was added.",
                                "field_count": 3,
                                "field_names": [
                                "ProfileChanged",
                                "CryptographicSetId",
                                "CryptographicSetName"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5046"
                            },
                            {
                                "event_id": 5049,
                                "category": "Logon/Logoff",
                                "subcategory": "IPsec Main Mode",
                                "message_summary": "An IPsec Security Association was deleted.",
                                "field_count": 3,
                                "field_names": [
                                "ProfileChanged",
                                "IpSecSecurityAssociationId",
                                "IpSecSecurityAssociationName"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5049"
                            },
                            {
                                "event_id": 5050,
                                "category": "System",
                                "subcategory": "Other System Events",
                                "message_summary": "An attempt to programmatically disable the Windows Firewall was rejected because this API is not supported on Windows Vista.",
                                "field_count": 3,
                                "field_names": [
                                "CallerProcessName",
                                "ProcessId",
                                "Publisher"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5050"
                            },
                            {
                                "event_id": 5051,
                                "category": "Object Access",
                                "subcategory": "File System",
                                "message_summary": "A file was virtualized.",
                                "field_count": 8,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "FileName",
                                "VirtualFileName",
                                "ProcessId",
                                "ProcessName"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5051"
                            },
                            {
                                "event_id": 5056,
                                "category": "System",
                                "subcategory": "System Integrity",
                                "message_summary": "A cryptographic self test was performed.",
                                "field_count": 6,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "Module",
                                "ReturnCode"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5056"
                            },
                            {
                                "event_id": 5057,
                                "category": "System",
                                "subcategory": "System Integrity",
                                "message_summary": "A cryptographic primitive operation failed.",
                                "field_count": 8,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "ProviderName",
                                "AlgorithmName",
                                "Reason",
                                "ReturnCode"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5057"
                            },
                            {
                                "event_id": 5058,
                                "category": "System",
                                "subcategory": "Other System Events",
                                "message_summary": "Key file operation.",
                                "field_count": 11,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "ProviderName",
                                "AlgorithmName",
                                "KeyName",
                                "KeyType",
                                "KeyFilePath",
                                "Operation",
                                "ReturnCode"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5058"
                            },
                            {
                                "event_id": 5059,
                                "category": "System",
                                "subcategory": "Other System Events",
                                "message_summary": "Key migration operation.",
                                "field_count": 10,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "ProviderName",
                                "AlgorithmName",
                                "KeyName",
                                "KeyType",
                                "Operation",
                                "ReturnCode"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5059"
                            },
                            {
                                "event_id": 5060,
                                "category": "System",
                                "subcategory": "System Integrity",
                                "message_summary": "Verification operation failed.",
                                "field_count": 10,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "ProviderName",
                                "AlgorithmName",
                                "KeyName",
                                "KeyType",
                                "Reason",
                                "ReturnCode"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5060"
                            },
                            {
                                "event_id": 5062,
                                "category": "System",
                                "subcategory": "System Integrity",
                                "message_summary": "A kernel-mode cryptographic self test was performed.",
                                "field_count": 2,
                                "field_names": [
                                "Module",
                                "ReturnCode"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5062"
                            },
                            {
                                "event_id": 5063,
                                "category": "Policy Change",
                                "subcategory": "Other Policy Change Events",
                                "message_summary": "A cryptographic provider operation was attempted.",
                                "field_count": 8,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "ProviderName",
                                "ModuleName",
                                "Operation",
                                "ReturnCode"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5063"
                            },
                            {
                                "event_id": 5064,
                                "category": "Policy Change",
                                "subcategory": "Other Policy Change Events",
                                "message_summary": "A cryptographic context operation was attempted.",
                                "field_count": 8,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "Scope",
                                "ContextName",
                                "Operation",
                                "ReturnCode"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5064"
                            },
                            {
                                "event_id": 5065,
                                "category": "Policy Change",
                                "subcategory": "Other Policy Change Events",
                                "message_summary": "A cryptographic context modification was attempted.",
                                "field_count": 9,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "Scope",
                                "ContextName",
                                "OldValue",
                                "NewValue",
                                "ReturnCode"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5065"
                            },
                            {
                                "event_id": 5066,
                                "category": "Policy Change",
                                "subcategory": "Other Policy Change Events",
                                "message_summary": "A cryptographic function operation was attempted.",
                                "field_count": 11,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "Scope",
                                "ContextName",
                                "InterfaceId",
                                "FunctionName",
                                "Position",
                                "Operation",
                                "ReturnCode"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5066"
                            },
                            {
                                "event_id": 5067,
                                "category": "Policy Change",
                                "subcategory": "Other Policy Change Events",
                                "message_summary": "A cryptographic function modification was attempted.",
                                "field_count": 11,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "Scope",
                                "ContextName",
                                "InterfaceId",
                                "FunctionName",
                                "OldValue",
                                "NewValue",
                                "ReturnCode"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5067"
                            },
                            {
                                "event_id": 5068,
                                "category": "Policy Change",
                                "subcategory": "Other Policy Change Events",
                                "message_summary": "A cryptographic function provider operation was attempted.",
                                "field_count": 12,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "Scope",
                                "ContextName",
                                "InterfaceId",
                                "FunctionName",
                                "ProviderName",
                                "Position",
                                "Operation",
                                "ReturnCode"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5068"
                            },
                            {
                                "event_id": 5069,
                                "category": "Policy Change",
                                "subcategory": "Other Policy Change Events",
                                "message_summary": "A cryptographic function property operation was attempted.",
                                "field_count": 12,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "Scope",
                                "ContextName",
                                "InterfaceId",
                                "FunctionName",
                                "PropertyName",
                                "Operation",
                                "Value",
                                "ReturnCode"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5069"
                            },
                            {
                                "event_id": 5070,
                                "category": "Policy Change",
                                "subcategory": "Other Policy Change Events",
                                "message_summary": "A cryptographic function property modification was attempted.",
                                "field_count": 12,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "Scope",
                                "ContextName",
                                "InterfaceId",
                                "FunctionName",
                                "PropertyName",
                                "OldValue",
                                "NewValue",
                                "ReturnCode"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5070"
                            },
                            {
                                "event_id": 5122,
                                "category": "Object Access",
                                "subcategory": "Certification Services",
                                "message_summary": "A Configuration entry changed in the OCSP Responder Service.",
                                "field_count": 6,
                                "field_names": [
                                "CAConfigurationId",
                                "NewValue",
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5122"
                            },
                            {
                                "event_id": 5123,
                                "category": "Object Access",
                                "subcategory": "Certification Services",
                                "message_summary": "A configuration entry changed in the OCSP Responder Service.",
                                "field_count": 6,
                                "field_names": [
                                "PropertyName",
                                "NewValue",
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5123"
                            },
                            {
                                "event_id": 5124,
                                "category": "Object Access",
                                "subcategory": "Certification Services",
                                "message_summary": "A security setting was updated on OCSP Responder Service.",
                                "field_count": 5,
                                "field_names": [
                                "NewSecuritySettings",
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5124"
                            },
                            {
                                "event_id": 5126,
                                "category": "Object Access",
                                "subcategory": "Certification Services",
                                "message_summary": "Signing Certificate was automatically updated by the OCSP Responder Service.",
                                "field_count": 2,
                                "field_names": [
                                "CAConfigurationId",
                                "NewSigningCertificateHash"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5126"
                            },
                            {
                                "event_id": 5127,
                                "category": "Object Access",
                                "subcategory": "Certification Services",
                                "message_summary": "The OCSP Revocation Provider successfully updated the revocation information.",
                                "field_count": 8,
                                "field_names": [
                                "CAConfigurationId",
                                "BaseCRLNumber",
                                "BaseCRLThisUpdate",
                                "BaseCRLHash",
                                "DeltaCRLNumber",
                                "DeltaCRLIndicator",
                                "DeltaCRLThisUpdate",
                                "DeltaCRLHash"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5127"
                            },
                            {
                                "event_id": 5136,
                                "category": "DS Access",
                                "subcategory": "Directory Service Changes",
                                "message_summary": "A directory service object was modified.",
                                "field_count": 15,
                                "field_names": [
                                "OpCorrelationID",
                                "AppCorrelationID",
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "DSName",
                                "DSType",
                                "ObjectDN",
                                "ObjectGUID",
                                "ObjectClass",
                                "AttributeLDAPDisplayName",
                                "AttributeSyntaxOID",
                                "AttributeValue",
                                "OperationType"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5136"
                            },
                            {
                                "event_id": 5137,
                                "category": "DS Access",
                                "subcategory": "Directory Service Changes",
                                "message_summary": "A directory service object was created.",
                                "field_count": 11,
                                "field_names": [
                                "OpCorrelationID",
                                "AppCorrelationID",
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "DSName",
                                "DSType",
                                "ObjectDN",
                                "ObjectGUID",
                                "ObjectClass"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5137"
                            },
                            {
                                "event_id": 5138,
                                "category": "DS Access",
                                "subcategory": "Directory Service Changes",
                                "message_summary": "A directory service object was undeleted.",
                                "field_count": 12,
                                "field_names": [
                                "OpCorrelationID",
                                "AppCorrelationID",
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "DSName",
                                "DSType",
                                "OldObjectDN",
                                "NewObjectDN",
                                "ObjectGUID",
                                "ObjectClass"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5138"
                            },
                            {
                                "event_id": 5140,
                                "category": "Object Access",
                                "subcategory": "File Share",
                                "message_summary": "A network share object was accessed.",
                                "field_count": 11,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "ObjectType",
                                "IpAddress",
                                "IpPort",
                                "ShareName",
                                "ShareLocalPath",
                                "AccessMask",
                                "AccessList"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5140"
                            },
                            {
                                "event_id": 5141,
                                "category": "DS Access",
                                "subcategory": "Directory Service Changes",
                                "message_summary": "A directory service object was deleted.",
                                "field_count": 12,
                                "field_names": [
                                "OpCorrelationID",
                                "AppCorrelationID",
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "DSName",
                                "DSType",
                                "ObjectDN",
                                "ObjectGUID",
                                "ObjectClass",
                                "TreeDelete"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5141"
                            },
                            {
                                "event_id": 5142,
                                "category": "Object Access",
                                "subcategory": "File Share",
                                "message_summary": "A network share object was added.",
                                "field_count": 6,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "ShareName",
                                "ShareLocalPath"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5142"
                            },
                            {
                                "event_id": 5143,
                                "category": "Object Access",
                                "subcategory": "File Share",
                                "message_summary": "A network share object was modified.",
                                "field_count": 15,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "ObjectType",
                                "ShareName",
                                "ShareLocalPath",
                                "OldRemark",
                                "NewRemark",
                                "OldMaxUsers",
                                "NewMaxUsers",
                                "OldShareFlags",
                                "NewShareFlags",
                                "OldSD",
                                "NewSD"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5143"
                            },
                            {
                                "event_id": 5145,
                                "category": "Object Access",
                                "subcategory": "Detailed File Share",
                                "message_summary": "A network share object was checked to see whether the client can be granted desired access.",
                                "field_count": 13,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "ObjectType",
                                "IpAddress",
                                "IpPort",
                                "ShareName",
                                "ShareLocalPath",
                                "RelativeTargetName",
                                "AccessMask",
                                "AccessList",
                                "AccessReason"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5145"
                            },
                            {
                                "event_id": 5148,
                                "category": "Object Access",
                                "subcategory": "Other Object Access Events",
                                "message_summary": "The Windows Filtering Platform has detected a DoS attack and entered a defensive mode; packets associated with this attack will be discarded.",
                                "field_count": 1,
                                "field_names": [
                                "Type"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5148"
                            },
                            {
                                "event_id": 5149,
                                "category": "Object Access",
                                "subcategory": "Other Object Access Events",
                                "message_summary": "The DoS attack has subsided and normal processing is being resumed.",
                                "field_count": 2,
                                "field_names": [
                                "Type",
                                "PacketsDiscarded"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5149"
                            },
                            {
                                "event_id": 5150,
                                "category": "Object Access",
                                "subcategory": "Filtering Platform Connection",
                                "message_summary": "The Windows Filtering Platform has blocked a packet.",
                                "field_count": 11,
                                "field_names": [
                                "Direction",
                                "SourceAddress",
                                "DestAddress",
                                "EtherType",
                                "EncapMethod",
                                "SnapControl",
                                "SnapOui",
                                "VlanTag",
                                "FilterRTID",
                                "LayerName",
                                "LayerRTID"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5150"
                            },
                            {
                                "event_id": 5152,
                                "category": "Object Access",
                                "subcategory": "Filtering Platform Packet Drop ",
                                "message_summary": "The Windows Filtering Platform blocked a packet.",
                                "field_count": 11,
                                "field_names": [
                                "ProcessId",
                                "Application",
                                "Direction",
                                "SourceAddress",
                                "SourcePort",
                                "DestAddress",
                                "DestPort",
                                "Protocol",
                                "FilterRTID",
                                "LayerName",
                                "LayerRTID"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5152"
                            },
                            {
                                "event_id": 5154,
                                "category": "Object Access",
                                "subcategory": "Filtering Platform Connection",
                                "message_summary": "The Windows Filtering Platform has permitted an application or service to listen on a port for incoming connections.",
                                "field_count": 8,
                                "field_names": [
                                "ProcessId",
                                "Application",
                                "SourceAddress",
                                "SourcePort",
                                "Protocol",
                                "FilterRTID",
                                "LayerName",
                                "LayerRTID"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5154"
                            },
                            {
                                "event_id": 5156,
                                "category": "Object Access",
                                "subcategory": "Filtering Platform Connection",
                                "message_summary": "The Windows Filtering Platform has allowed a connection.",
                                "field_count": 13,
                                "field_names": [
                                "ProcessID",
                                "Application",
                                "Direction",
                                "SourceAddress",
                                "SourcePort",
                                "DestAddress",
                                "DestPort",
                                "Protocol",
                                "FilterRTID",
                                "LayerName",
                                "LayerRTID",
                                "RemoteUserID",
                                "RemoteMachineID"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5156"
                            },
                            {
                                "event_id": 5168,
                                "category": "Object Access",
                                "subcategory": "File Share",
                                "message_summary": "Spn check for SMB/SMB2 failed.",
                                "field_count": 9,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "SpnName",
                                "ErrorCode",
                                "ServerNames",
                                "ConfiguredNames",
                                "IpAddresses"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5168"
                            },
                            {
                                "event_id": 5378,
                                "category": "Logon/Logoff",
                                "subcategory": "Other Logon/Logoff Events",
                                "message_summary": "The requested credentials delegation was disallowed by policy.",
                                "field_count": 8,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "Package",
                                "UserUPN",
                                "TargetServer",
                                "CredType"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5378"
                            },
                            {
                                "event_id": 5440,
                                "category": "Policy Change",
                                "subcategory": "Filtering Platform Policy Change",
                                "message_summary": "The following callout was present when the Windows Filtering Platform Base Filtering Engine started.",
                                "field_count": 9,
                                "field_names": [
                                "ProviderKey",
                                "ProviderName",
                                "CalloutKey",
                                "CalloutName",
                                "CalloutType",
                                "CalloutId",
                                "LayerKey",
                                "LayerName",
                                "LayerId"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5440"
                            },
                            {
                                "event_id": 5441,
                                "category": "Policy Change",
                                "subcategory": "Filtering Platform Policy Change",
                                "message_summary": "The following filter was present when the Windows Filtering Platform Base Filtering Engine started.",
                                "field_count": 14,
                                "field_names": [
                                "ProviderKey",
                                "ProviderName",
                                "FilterKey",
                                "FilterName",
                                "FilterType",
                                "FilterId",
                                "LayerKey",
                                "LayerName",
                                "LayerId",
                                "Weight",
                                "Conditions",
                                "Action",
                                "CalloutKey",
                                "CalloutName"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5441"
                            },
                            {
                                "event_id": 5442,
                                "category": "Policy Change",
                                "subcategory": "Filtering Platform Policy Change",
                                "message_summary": "The following provider was present when the Windows Filtering Platform Base Filtering Engine started.",
                                "field_count": 3,
                                "field_names": [
                                "ProviderKey",
                                "ProviderName",
                                "ProviderType"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5442"
                            },
                            {
                                "event_id": 5443,
                                "category": "Policy Change",
                                "subcategory": "Filtering Platform Policy Change",
                                "message_summary": "The following provider context was present when the Windows Filtering Platform Base Filtering Engine started.",
                                "field_count": 5,
                                "field_names": [
                                "ProviderKey",
                                "ProviderName",
                                "ProviderContextKey",
                                "ProviderContextName",
                                "ProviderContextType"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5443"
                            },
                            {
                                "event_id": 5444,
                                "category": "Policy Change",
                                "subcategory": "Filtering Platform Policy Change",
                                "message_summary": "The following sub-layer was present when the Windows Filtering Platform Base Filtering Engine started.",
                                "field_count": 6,
                                "field_names": [
                                "ProviderKey",
                                "ProviderName",
                                "SubLayerKey",
                                "SubLayerName",
                                "SubLayerType",
                                "Weight"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5444"
                            },
                            {
                                "event_id": 5446,
                                "category": "Policy Change",
                                "subcategory": "Filtering Platform Policy Change",
                                "message_summary": "A Windows Filtering Platform callout has been changed.",
                                "field_count": 13,
                                "field_names": [
                                "ProcessId",
                                "UserSid",
                                "UserName",
                                "ProviderKey",
                                "ProviderName",
                                "ChangeType",
                                "CalloutKey",
                                "CalloutName",
                                "CalloutType",
                                "CalloutId",
                                "LayerKey",
                                "LayerName",
                                "LayerId"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5446"
                            },
                            {
                                "event_id": 5447,
                                "category": "Policy Change",
                                "subcategory": "Other Policy Change Events",
                                "message_summary": "A Windows Filtering Platform filter has been changed.",
                                "field_count": 18,
                                "field_names": [
                                "ProcessId",
                                "UserSid",
                                "UserName",
                                "ProviderKey",
                                "ProviderName",
                                "ChangeType",
                                "FilterKey",
                                "FilterName",
                                "FilterType",
                                "FilterId",
                                "LayerKey",
                                "LayerName",
                                "LayerId",
                                "Weight",
                                "Conditions",
                                "Action",
                                "CalloutKey",
                                "CalloutName"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5447"
                            },
                            {
                                "event_id": 5448,
                                "category": "Policy Change",
                                "subcategory": "Filtering Platform Policy Change",
                                "message_summary": "A Windows Filtering Platform provider has been changed.",
                                "field_count": 7,
                                "field_names": [
                                "ProcessId",
                                "UserSid",
                                "UserName",
                                "ChangeType",
                                "ProviderKey",
                                "ProviderName",
                                "ProviderType"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5448"
                            },
                            {
                                "event_id": 5449,
                                "category": "Policy Change",
                                "subcategory": "Filtering Platform Policy Change",
                                "message_summary": "A Windows Filtering Platform provider context has been changed.",
                                "field_count": 9,
                                "field_names": [
                                "ProcessId",
                                "UserSid",
                                "UserName",
                                "ProviderKey",
                                "ProviderName",
                                "ChangeType",
                                "ProviderContextKey",
                                "ProviderContextName",
                                "ProviderContextType"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5449"
                            },
                            {
                                "event_id": 5450,
                                "category": "Policy Change",
                                "subcategory": "Filtering Platform Policy Change",
                                "message_summary": "A Windows Filtering Platform sub-layer has been changed.",
                                "field_count": 10,
                                "field_names": [
                                "ProcessId",
                                "UserSid",
                                "UserName",
                                "ProviderKey",
                                "ProviderName",
                                "ChangeType",
                                "SubLayerKey",
                                "SubLayerName",
                                "SubLayerType",
                                "Weight"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5450"
                            },
                            {
                                "event_id": 5451,
                                "category": "Logon/Logoff",
                                "subcategory": "IPsec Quick Mode",
                                "message_summary": "An IPsec Quick Mode security association was established.",
                                "field_count": 26,
                                "field_names": [
                                "LocalAddress",
                                "LocalAddressMask",
                                "LocalPort",
                                "LocalTunnelEndpoint",
                                "RemoteAddress",
                                "RemoteAddressMask",
                                "RemotePort",
                                "PeerPrivateAddress",
                                "RemoteTunnelEndpoint",
                                "IpProtocol",
                                "KeyingModuleName",
                                "AhAuthType",
                                "EspAuthType",
                                "CipherType",
                                "LifetimeSeconds",
                                "LifetimeKilobytes",
                                "LifetimePackets",
                                "Mode",
                                "Role",
                                "TransportFilterId",
                                "MainModeSaId",
                                "QuickModeSaId",
                                "InboundSpi",
                                "OutboundSpi",
                                "TunnelId",
                                "TrafficSelectorId"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5451"
                            },
                            {
                                "event_id": 5452,
                                "category": "Logon/Logoff",
                                "subcategory": "IPsec Quick Mode",
                                "message_summary": "An IPsec Quick Mode security association ended.",
                                "field_count": 10,
                                "field_names": [
                                "LocalAddress",
                                "LocalPort",
                                "LocalTunnelEndpoint",
                                "RemoteAddress",
                                "RemotePort",
                                "RemoteTunnelEndpoint",
                                "IpProtocol",
                                "QuickModeSaId",
                                "TunnelId",
                                "TrafficSelectorId"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5452"
                            },
                            {
                                "event_id": 5456,
                                "category": "Policy Change",
                                "subcategory": "Filtering Platform Policy Change",
                                "message_summary": "PAStore Engine applied Active Directory storage IPsec policy on the computer.",
                                "field_count": 1,
                                "field_names": [
                                "Policy"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5456"
                            },
                            {
                                "event_id": 5457,
                                "category": "Policy Change",
                                "subcategory": "Filtering Platform Policy Change",
                                "message_summary": "PAStore Engine failed to apply Active Directory storage IPsec policy on the computer.",
                                "field_count": 2,
                                "field_names": [
                                "Policy",
                                "Error"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5457"
                            },
                            {
                                "event_id": 5477,
                                "category": "Policy Change",
                                "subcategory": "Filtering Platform Policy Change",
                                "message_summary": "PAStore Engine failed to add quick mode filter.",
                                "field_count": 2,
                                "field_names": [
                                "QuickModeFilter",
                                "Error"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5477"
                            },
                            {
                                "event_id": 5483,
                                "category": "System",
                                "subcategory": "IPsec Driver",
                                "message_summary": "IPsec Services failed to initialize RPC server. IPsec Services could not be started.",
                                "field_count": 1,
                                "field_names": [
                                "Error"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5483"
                            },
                            {
                                "event_id": 5632,
                                "category": "Logon/Logoff",
                                "subcategory": "Other Logon/Logoff Events",
                                "message_summary": "A request was made to authenticate to a wireless network.",
                                "field_count": 14,
                                "field_names": [
                                "SSID",
                                "Identity",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "PeerMac",
                                "LocalMac",
                                "IntfGuid",
                                "ReasonCode",
                                "ReasonText",
                                "ErrorCode",
                                "EAPReasonCode",
                                "EapRootCauseString",
                                "EAPErrorCode"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5632"
                            },
                            {
                                "event_id": 5633,
                                "category": "Logon/Logoff",
                                "subcategory": "Other Logon/Logoff Events",
                                "message_summary": "A request was made to authenticate to a wired network.",
                                "field_count": 8,
                                "field_names": [
                                "InterfaceName",
                                "Identity",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "ReasonCode",
                                "ReasonText",
                                "ErrorCode"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5633"
                            },
                            {
                                "event_id": 5712,
                                "category": "Detailed Tracking",
                                "subcategory": "RPC Events",
                                "message_summary": "A Remote Procedure Call (RPC) was attempted.",
                                "field_count": 12,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "SubjectLogonId",
                                "ProcessId",
                                "ProcessName",
                                "RemoteIpAddress",
                                "RemotePort",
                                "InterfaceUuid",
                                "ProtocolSequence",
                                "AuthenticationService",
                                "AuthenticationLevel"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5712"
                            },
                            {
                                "event_id": 5888,
                                "category": "Object Access",
                                "subcategory": "Other Object Access Events",
                                "message_summary": "An object in the COM+ Catalog was modified.",
                                "field_count": 7,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectUserDomainName",
                                "SubjectLogonId",
                                "ObjectCollectionName",
                                "ObjectIdentifyingProperties",
                                "ModifiedObjectProperties"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5888"
                            },
                            {
                                "event_id": 5889,
                                "category": "Object Access",
                                "subcategory": "Other Object Access Events",
                                "message_summary": "An object was deleted from the COM+ Catalog.",
                                "field_count": 7,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectUserDomainName",
                                "SubjectLogonId",
                                "ObjectCollectionName",
                                "ObjectIdentifyingProperties",
                                "ObjectProperties"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5889"
                            },
                            {
                                "event_id": 6144,
                                "category": "Policy Change",
                                "subcategory": "Other Policy Change Events",
                                "message_summary": "Security policy in the group policy objects has been applied successfully.",
                                "field_count": 2,
                                "field_names": [
                                "ErrorCode",
                                "GPOList"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-6144"
                            },
                            {
                                "event_id": 6272,
                                "category": "Logon/Logoff",
                                "subcategory": "Network Policy Server",
                                "message_summary": "Network Policy Server granted access to a user.",
                                "field_count": 27,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "FullyQualifiedSubjectUserName",
                                "SubjectMachineSID",
                                "SubjectMachineName",
                                "FullyQualifiedSubjectMachineName",
                                "MachineInventory",
                                "CalledStationID",
                                "CallingStationID",
                                "NASIPv4Address",
                                "NASIPv6Address",
                                "NASIdentifier",
                                "NASPortType",
                                "NASPort",
                                "ClientName",
                                "ClientIPAddress",
                                "ProxyPolicyName",
                                "NetworkPolicyName",
                                "AuthenticationProvider",
                                "AuthenticationServer",
                                "AuthenticationType",
                                "EAPType",
                                "AccountSessionIdentifier",
                                "QuarantineState",
                                "QuarantineSessionIdentifier",
                                "LoggingResult"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-6272"
                            },
                            {
                                "event_id": 6273,
                                "category": "Logon/Logoff",
                                "subcategory": "Network Policy Server",
                                "message_summary": "Network Policy Server denied access to a user.",
                                "field_count": 27,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "FullyQualifiedSubjectUserName",
                                "SubjectMachineSID",
                                "SubjectMachineName",
                                "FullyQualifiedSubjectMachineName",
                                "MachineInventory",
                                "CalledStationID",
                                "CallingStationID",
                                "NASIPv4Address",
                                "NASIPv6Address",
                                "NASIdentifier",
                                "NASPortType",
                                "NASPort",
                                "ClientName",
                                "ClientIPAddress",
                                "ProxyPolicyName",
                                "NetworkPolicyName",
                                "AuthenticationProvider",
                                "AuthenticationServer",
                                "AuthenticationType",
                                "EAPType",
                                "AccountSessionIdentifier",
                                "ReasonCode",
                                "Reason",
                                "LoggingResult"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-6273"
                            },
                            {
                                "event_id": 6276,
                                "category": "Logon/Logoff",
                                "subcategory": "Network Policy Server",
                                "message_summary": "Network Policy Server quarantined a user.",
                                "field_count": 29,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "FullyQualifiedSubjectUserName",
                                "SubjectMachineSID",
                                "SubjectMachineName",
                                "FullyQualifiedSubjectMachineName",
                                "MachineInventory",
                                "CalledStationID",
                                "CallingStationID",
                                "NASIPv4Address",
                                "NASIPv6Address",
                                "NASIdentifier",
                                "NASPortType",
                                "NASPort",
                                "ClientName",
                                "ClientIPAddress",
                                "ProxyPolicyName",
                                "NetworkPolicyName",
                                "AuthenticationProvider",
                                "AuthenticationServer",
                                "AuthenticationType",
                                "EAPType",
                                "AccountSessionIdentifier",
                                "QuarantineState",
                                "ExtendedQuarantineState",
                                "QuarantineSessionID",
                                "QuarantineHelpURL",
                                "QuarantineSystemHealthResult"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-6276"
                            },
                            {
                                "event_id": 6277,
                                "category": "Logon/Logoff",
                                "subcategory": "Network Policy Server",
                                "message_summary": "Network Policy Server granted access to a user but put it on probation because the host did not meet the defined health policy.",
                                "field_count": 30,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "FullyQualifiedSubjectUserName",
                                "SubjectMachineSID",
                                "SubjectMachineName",
                                "FullyQualifiedSubjectMachineName",
                                "MachineInventory",
                                "CalledStationID",
                                "CallingStationID",
                                "NASIPv4Address",
                                "NASIPv6Address",
                                "NASIdentifier",
                                "NASPortType",
                                "NASPort",
                                "ClientName",
                                "ClientIPAddress",
                                "ProxyPolicyName",
                                "NetworkPolicyName",
                                "AuthenticationProvider",
                                "AuthenticationServer",
                                "AuthenticationType",
                                "EAPType",
                                "AccountSessionIdentifier",
                                "QuarantineState",
                                "ExtendedQuarantineState",
                                "QuarantineSessionID",
                                "QuarantineHelpURL",
                                "QuarantineSystemHealthResult",
                                "QuarantineGraceTime"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-6277"
                            },
                            {
                                "event_id": 6279,
                                "category": "Logon/Logoff",
                                "subcategory": "Network Policy Server",
                                "message_summary": "Network Policy Server locked the user account due to repeated failed authentication attempts.",
                                "field_count": 4,
                                "field_names": [
                                "SubjectUserSid",
                                "SubjectUserName",
                                "SubjectDomainName",
                                "FullyQualifiedSubjectUserName"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-6279"
                            },
                            {
                                "event_id": 6400,
                                "category": "System",
                                "subcategory": "Other System Events",
                                "message_summary": "BranchCache: Received an incorrectly formatted response while discovering availability of content. ",
                                "field_count": 1,
                                "field_names": [
                                "ClientIPAddress"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-6400"
                            },
                            {
                                "event_id": 6403,
                                "category": "System",
                                "subcategory": "Other System Events",
                                "message_summary": "BranchCache: The hosted cache sent an incorrectly formatted response to the client.",
                                "field_count": 1,
                                "field_names": [
                                "HostedCacheName"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-6403"
                            },
                            {
                                "event_id": 6404,
                                "category": "System",
                                "subcategory": "Other System Events",
                                "message_summary": "BranchCache: Hosted cache could not be authenticated using the provisioned SSL certificate. ",
                                "field_count": 2,
                                "field_names": [
                                "HostedCacheName",
                                "ErrorCode"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-6404"
                            },
                            {
                                "event_id": 6405,
                                "category": "System",
                                "subcategory": "Other System Events",
                                "message_summary": "BranchCache: %2 instance(s) of event id %1 occurred.",
                                "field_count": 2,
                                "field_names": [
                                "EventId",
                                "Count"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-6405"
                            },
                            {
                                "event_id": 6406,
                                "category": "System",
                                "subcategory": "Other System Events",
                                "message_summary": "%1 registered to Windows Firewall to control filtering for the following: %2",
                                "field_count": 2,
                                "field_names": [
                                "ProductName",
                                "Categories"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-6406"
                            },
                            {
                                "event_id": 6407,
                                "category": "System",
                                "subcategory": "Other System Events",
                                "message_summary": "1%",
                                "field_count": 1,
                                "field_names": [
                                "Message"
                                ],
                                "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-6407"
                            }
                            ];
            
           this.processData();
            this.populateFilters();
            this.filterEvents();
            
            console.log(`✓ Loaded ${this.events.length} events`);
        } catch (error) {
            console.error('Error loading data:', error);
            this.resultsTable.innerHTML = '<div class="no-results">Error loading event data</div>';
        }
    }

    processData() {
        this.events.forEach(event => {
            this.allCategories.add(event.category);
            this.allSubcategories.add(event.subcategory);
            event.field_names.forEach(field => this.allFieldNames.add(field));
        });
    }

    populateFilters() {
        // Populate categories
        Array.from(this.allCategories).sort().forEach(category => {
            const option = document.createElement('option');
            option.value = category;
            option.textContent = category;
            this.categorySelect.appendChild(option);
        });

        // Populate subcategories
        Array.from(this.allSubcategories).sort().forEach(subcategory => {
            const option = document.createElement('option');
            option.value = subcategory;
            option.textContent = subcategory;
            this.subcategorySelect.appendChild(option);
        });

        // Create field search and populate field names
        this.createFieldSearch();
    }

    createFieldSearch() {
        // Create field search container
        const searchContainer = document.createElement('div');
        searchContainer.className = 'field-search-container';
        
        const searchInput = document.createElement('input');
        searchInput.type = 'text';
        searchInput.id = 'fieldSearch';
        searchInput.placeholder = 'search fields...';
        searchInput.className = 'field-search-input';
        
        const selectAllBtn = document.createElement('button');
        selectAllBtn.type = 'button';
        selectAllBtn.className = 'field-select-all-btn';
        selectAllBtn.textContent = 'select all visible';
        
        const clearAllBtn = document.createElement('button');
        clearAllBtn.type = 'button';
        clearAllBtn.className = 'field-clear-all-btn';
        clearAllBtn.textContent = 'clear all';
        
        const controlsDiv = document.createElement('div');
        controlsDiv.className = 'field-controls';
        controlsDiv.appendChild(selectAllBtn);
        controlsDiv.appendChild(clearAllBtn);
        
        searchContainer.appendChild(searchInput);
        searchContainer.appendChild(controlsDiv);
        
        // Insert before field container
        this.fieldNamesContainer.parentNode.insertBefore(searchContainer, this.fieldNamesContainer);
        
        // Store references
        this.fieldSearchInput = searchInput;
        this.selectAllBtn = selectAllBtn;
        this.clearAllBtn = clearAllBtn;
        
        // Populate field checkboxes
        this.populateFieldCheckboxes();
        
        // Add event listeners for field search
        this.fieldSearchInput.addEventListener('input', () => this.filterFieldCheckboxes());
        this.selectAllBtn.addEventListener('click', () => this.selectAllVisibleFields());
        this.clearAllBtn.addEventListener('click', () => this.clearAllFields());
    }

    populateFieldCheckboxes() {
        const sortedFields = Array.from(this.allFieldNames).sort();
        
        sortedFields.forEach(fieldName => {
            const checkboxDiv = document.createElement('div');
            checkboxDiv.className = 'field-checkbox';
            checkboxDiv.dataset.fieldName = fieldName.toLowerCase();
            
            const checkbox = document.createElement('input');
            checkbox.type = 'checkbox';
            checkbox.id = `field_${fieldName}`;
            checkbox.value = fieldName;
            
            const label = document.createElement('label');
            label.htmlFor = `field_${fieldName}`;
            label.textContent = fieldName;
            
            checkboxDiv.appendChild(checkbox);
            checkboxDiv.appendChild(label);
            this.fieldNamesContainer.appendChild(checkboxDiv);
        });
    }

    filterFieldCheckboxes() {
        const searchTerm = this.fieldSearchInput.value.toLowerCase().trim();
        const checkboxes = this.fieldNamesContainer.querySelectorAll('.field-checkbox');
        
        checkboxes.forEach(checkbox => {
            const fieldName = checkbox.dataset.fieldName;
            const isVisible = fieldName.includes(searchTerm);
            checkbox.style.display = isVisible ? 'flex' : 'none';
        });
    }

    selectAllVisibleFields() {
        const visibleCheckboxes = this.fieldNamesContainer.querySelectorAll('.field-checkbox:not([style*="display: none"]) input');
        visibleCheckboxes.forEach(checkbox => {
            checkbox.checked = true;
        });
        this.filterEvents();
    }

    clearAllFields() {
        const checkboxes = this.fieldNamesContainer.querySelectorAll('input[type="checkbox"]');
        checkboxes.forEach(checkbox => {
            checkbox.checked = false;
        });
        this.filterEvents();
    }

    setupEventListeners() {
        // Real-time filtering
        this.eventIdInput.addEventListener('input', () => this.filterEvents());
        this.categorySelect.addEventListener('change', () => this.filterEvents());
        this.subcategorySelect.addEventListener('change', () => this.filterEvents());
        this.messageSearchInput.addEventListener('input', () => this.filterEvents());
        
        // Field checkboxes
        this.fieldNamesContainer.addEventListener('change', () => this.filterEvents());
        
        // Clear filters
        this.clearFiltersBtn.addEventListener('click', () => this.clearAllFilters());
    }

    filterEvents() {
        const eventId = this.eventIdInput.value.trim();
        const category = this.categorySelect.value;
        const subcategory = this.subcategorySelect.value;
        const messageSearch = this.messageSearchInput.value.toLowerCase().trim();
        const selectedFields = Array.from(this.fieldNamesContainer.querySelectorAll('input:checked'))
            .map(cb => cb.value);

        this.filteredEvents = this.events.filter(event => {
            // Event ID filter
            if (eventId && event.event_id.toString() !== eventId) {
                return false;
            }

            // Category filter
            if (category && event.category !== category) {
                return false;
            }

            // Subcategory filter
            if (subcategory && event.subcategory !== subcategory) {
                return false;
            }

            // Message search filter
            if (messageSearch && !event.message_summary.toLowerCase().includes(messageSearch)) {
                return false;
            }

            // Field names filter (event must have ALL selected fields)
            if (selectedFields.length > 0) {
                const hasAllFields = selectedFields.every(field => 
                    event.field_names.includes(field)
                );
                if (!hasAllFields) {
                    return false;
                }
            }

            return true;
        });

        this.displayResults();
    }

    displayResults() {
        this.resultsCount.textContent = `${this.filteredEvents.length} events found`;

        if (this.filteredEvents.length === 0) {
            this.resultsTable.innerHTML = '<div class="no-results">No events match your search criteria</div>';
            return;
        }

        // Clear previous results
        this.resultsTable.innerHTML = '';
        
        // Create each event card and add event listeners immediately
        this.filteredEvents.forEach((event, index) => {
            const eventCard = this.createEventCard(event, index);
            this.resultsTable.appendChild(eventCard);
        });
    }

    createEventCard(event, index) {
        const eventCard = document.createElement('div');
        eventCard.className = 'event-card';
        
        eventCard.innerHTML = `
            <div class="event-header">
                <div class="event-id">${event.event_id}</div>
                <div class="event-categories">
                    <span class="event-category">${event.category}</span>
                    <span class="event-category">${event.subcategory}</span>
                </div>
            </div>
            
            <div class="event-message">${event.message_summary}</div>
            
            <div class="event-fields">
                <div class="fields-header">Fields (${event.field_count}):</div>
                <div class="field-list-container">
                    <div class="field-list">
                        ${event.field_names.map(field => `<span class="field-tag">${field}</span>`).join('')}
                    </div>
                    <div class="field-actions">
                        <button class="copy-splunk-btn">copy Splunk Query</button>
                        <button class="copy-elastic-btn">copy Elastic Query</button>
                    </div>
                </div>
            </div>
            
            <div class="event-documentation">
                <a href="${event.documentation_url}" target="_blank" class="doc-link">
                    Microsoft Documentation
                </a>
                <a href="https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=${event.event_id}" target="_blank" class="doc-link ultimate-security-link">
                    Ultimate Windows Security
                </a>
            </div>
        `;
        
        // Add direct event listeners to the buttons
        const splunkBtn = eventCard.querySelector('.copy-splunk-btn');
        const elasticBtn = eventCard.querySelector('.copy-elastic-btn');
        
        splunkBtn.addEventListener('click', () => {
            const query = this.generateSplunkQuery(event);
            this.simpleCopy(query, splunkBtn);
        });
        
        elasticBtn.addEventListener('click', () => {
            const query = this.generateElasticQuery(event);
            this.simpleCopy(query, elasticBtn);
        });
        
        return eventCard;
    }

    // Simplified copy method that definitely works
    simpleCopy(text, button) {
        // Create a temporary textarea
        const textarea = document.createElement('textarea');
        textarea.value = text;
        textarea.style.position = 'fixed';
        textarea.style.opacity = '0';
        textarea.style.left = '-9999px';
        document.body.appendChild(textarea);
        
        // Store original button text
        const originalText = button.textContent;
        
        try {
            // Select and copy
            textarea.select();
            textarea.setSelectionRange(0, 99999); // For mobile
            const successful = document.execCommand('copy');
            
            if (successful) {
                // Success feedback
                button.textContent = 'copied!';
                button.style.background = 'linear-gradient(135deg, #10b981, #059669)';
                button.style.color = 'white';
                button.style.borderColor = '#10b981';
                
                setTimeout(() => {
                    button.textContent = originalText;
                    button.style.background = '';
                    button.style.color = '';
                    button.style.borderColor = '';
                }, 2000);
            } else {
                throw new Error('Copy command failed');
            }
        } catch (err) {
            console.error('Copy failed:', err);
            
            // Failure feedback
            button.textContent = 'failed';
            button.style.background = 'linear-gradient(135deg, #ef4444, #dc2626)';
            button.style.color = 'white';
            
            setTimeout(() => {
                button.textContent = originalText;
                button.style.background = '';
                button.style.color = '';
            }, 2000);
        } finally {
            // Clean up
            document.body.removeChild(textarea);
        }
    }

    generateSplunkQuery(eventData) {
        const fieldList = eventData.field_names.join(', ');
        return `EventCode=${eventData.event_id}
| table _time, host, ${fieldList}, _raw`;
    }

    generateElasticQuery(eventData) {
        const elasticFields = eventData.field_names.map(field => `winlog.event_data.${field}`);
        const keepFields = ['@timestamp', 'host.name', ...elasticFields, 'message'].join(', ');
        
        return `| where winlog.event_id == ${eventData.event_id}
| keep ${keepFields}`;
    }

    clearAllFilters() {
        this.eventIdInput.value = '';
        this.categorySelect.value = '';
        this.subcategorySelect.value = '';
        this.messageSearchInput.value = '';
        
        // Clear field search if it exists
        if (this.fieldSearchInput) {
            this.fieldSearchInput.value = '';
        }
        
        // Uncheck all field checkboxes
        this.fieldNamesContainer.querySelectorAll('input[type="checkbox"]').forEach(cb => {
            cb.checked = false;
        });
        
        // Show all field checkboxes
        this.fieldNamesContainer.querySelectorAll('.field-checkbox').forEach(cb => {
            cb.style.display = 'flex';
        });
        
        this.filterEvents();
    }
}

// Initialize the application when the page loads
document.addEventListener('DOMContentLoaded', () => {
    window.app = new WindowsEventsLookup();
});