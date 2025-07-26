# Windows Security Events Terminal

A comprehensive lookup tool for Windows Security Audit Events and their field definitions for cybersecurity professionals.


## 📝 How to Use

### 1. Basic Search
- **Event ID**: Enter a specific Windows Event ID (e.g., `4624` for successful logon)
- **Category**: Select from dropdown (System, Logon/Logoff, etc.)
- **Subcategory**: Filter by specific subcategory
- **Message Search**: Type keywords to search in event descriptions

### 2. Field-Based Filtering
- **Search Fields**: Use the search box to find specific field names
- **Multi-Select**: Check multiple fields to find events containing ALL selected fields
- **Quick Actions**:
  - `select all visible` - Select all currently filtered fields
  - `clear all` - Uncheck all selected fields

### 3. Query Generation
Each event result includes two query generation buttons:

#### 🔍 Splunk Query
Generates ready-to-use Splunk searches:
```spl
EventCode=4624
| table _time, host, SubjectUserSid, SubjectUserName, TargetUserSid, LogonType, _raw
```

#### ⚡ Elasticsearch Query  
Generates Elasticsearch/ELK queries:
```elasticsearch
| where winlog.event_id == 4624
| keep @timestamp, host.name, winlog.event_data.SubjectUserSid, winlog.event_data.SubjectUserName, message
```

### 4. Copy to Clipboard
- Click any query button to automatically copy to clipboard
- Visual feedback shows "copied!" confirmation
- Works in all modern browsers

## 🔧 Data Setup

### Adding Your Event Data

**Replace Sample Data**: In `script.js`, locate the `loadData()` method and replace the sample events:

```javascript
loadData() {
    try {
        this.events = [
            // Replace this array with your complete JSON data
            {
                "event_id": 4624,
                "category": "Logon/Logoff",
                "subcategory": "Logon",
                "message_summary": "An account was successfully logged on.",
                "field_count": 18,
                "field_names": ["SubjectUserSid", "SubjectUserName", ...],
                "documentation_url": "https://learn.microsoft.com/..."
            }
            // ... more events
        ];
```

### Expected JSON Format

```json
[
  {
    "event_id": 4624,
    "category": "Logon/Logoff", 
    "subcategory": "Logon",
    "message_summary": "An account was successfully logged on.",
    "field_count": 18,
    "field_names": ["SubjectUserSid", "SubjectUserName", "TargetUserSid"],
    "documentation_url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624"
  }
]
```
## 🔍 Search Tips

### Advanced Filtering
- **Combine Filters**: Use multiple filters together for precise results
- **Field Search**: Type partial field names (e.g., "User" finds all user-related fields)
- **Message Keywords**: Search descriptions with terms like "logon", "failed", "access"


## 📚 Resources

### Documentation Links
- [Microsoft Security Auditing Events](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/)
- [Ultimate Windows Security Encyclopedia](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/)

## 🤝 Contributing

1. Fork the repository
2. Add new features or improvements
3. Test thoroughly across browsers
4. Submit pull request with clear description

**Happy Hunting! 🛡️**

*Built with ❤️ for the cybersecurity community*