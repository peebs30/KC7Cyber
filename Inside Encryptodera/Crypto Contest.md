###### What is the filename of this note?
```kql
search "YOU_GOT_CRYTOED"
```

###### On how many machines was this .txt file seen?
```kql
search "YOU_GOT_CRYTOED"
| distinct hostname
| count
```

###### What time was the ransom note first seen?
```kql
FileCreationEvents
| where filename startswith "YOU_GOT_CRYTOED"
| top 1 by timestamp asc 
```

###### What is the hostname of the system where the ransom note was first seen?
```kql
FileCreationEvents
| where filename startswith "YOU_GOT_CRYTOED"
| top 1 by timestamp asc 
```

###### How many files were encrypted on this machine?
```kql
let eventTime = todatetime("2024-02-17T02:34:54Z");
ProcessEvents
| where timestamp between ((eventTime - 10m) .. (eventTime + 10m))
| where hostname =~ "UL8R-MACHINE"
| extend Relevance = iff(timestamp > eventTime, "Later", iff(timestamp < eventTime, "Prior", "Event"))
| project-reorder Relevance

FileCreationEvents
| where filename endswith ".umadbro" and hostname =~ "UL8R-MACHINE"
| count
```

###### **When did `files_go_byebye.exe` appear on this machine?**
```kql
FileCreationEvents
| where filename =~ "files_go_byebye.exe" and hostname =~ "UL8R-MACHINE"
```

###### How many commands were run on UL8R-MACHINE during this timeframe?
```kql
ProcessEvents
| where hostname == "UL8R-MACHINE"
| where timestamp between (datetime("2024-02-16") .. datetime("2024-02-18"))
```

###### **What domain does the encoded PowerShell reference?**
```kql
ProcessEvents
| where process_commandline has_any ("-encoded","-enc","-e") and hostname =~ "UL8R-MACHINE"
| extend base64String = extract(@'\s+([A-Za-z0-9+/]{20}\S+$)', 1, process_commandline)
| extend DecodedCommandLine = base64_decode_tostring(base64String)
```

###### What command is run right before the base64-encoded PowerShell?
```kql
let eventTime = todatetime("2024-02-17T02:29:53Z");
ProcessEvents
| where timestamp between ((eventTime - 10m) .. (eventTime + 10m))
| where hostname =~ "UL8R-MACHINE"
| extend Relevance = iff(timestamp > eventTime, "Later", iff(timestamp < eventTime, "Prior", "Event"))
| project-reorder Relevance
```

###### How many devices ran the gpupdate /force command?
```kql
ProcessEvents
| where process_commandline =~ "gpupdate /force"
| distinct hostname
| count
```

###### How many machines at Encryptodera ran "systeminfo"?
```kql
ProcessEvents
| where process_commandline =~ "systeminfo"
| distinct hostname
| count
```

###### What was the timestamp for the first time the command was run?
```kql
ProcessEvents
| where process_commandline =~ "systeminfo"
| top 1 by timestamp asc
```

###### What was the full commandline used by the threat actor when running nltest /dclist?
```kql
let eventTime = todatetime("2024-02-02T03:32:36Z");
ProcessEvents
| where timestamp between ((eventTime - 10m) .. (eventTime + 60m))
| where hostname =~ "41QI-LAPTOP"
| extend Relevance = iff(timestamp > eventTime, "Later", iff(timestamp < eventTime, "Prior", "Event"))
| project-reorder Relevance
```

###### What is the full name of the .xlsx.exe file on 41QI-LAPTOP?
```kql
FileCreationEvents
| where hostname =~ "41QI-LAPTOP" and filename endswith ".xlsx.exe"
```

###### What file shows up a few seconds after the .xlsx.exe file?
```kql
let eventTime = todatetime("2024-02-01T08:50:12Z");
FileCreationEvents
| where timestamp between ((eventTime - 10m) .. (eventTime + 1m))
| where hostname =~ "41QI-LAPTOP"
| extend Relevance = iff(timestamp > eventTime, "Later", iff(timestamp < eventTime, "Prior", "Event"))
| project-reorder Relevance
```

###### How many devices does screenconnect_client.exe appear on?
```kql
FileCreationEvents
| where filename =~ "screenconnect_client.exe"
| distinct hostname
| count
```

###### Check the Email logs to see if the .xlsx.exe file was sent in a link. What email address was used to send this file?
```kql
Email
| where link contains ".xlsx.exe"
```

###### How many unusual emails were sent by Barry?
```kql
Email
| where timestamp > todatetime("2024-02-01") and sender =~ "barry_shmelly@encryptoderafinancial.com"
```

###### What IP was used to sign in to Barry's account on February 1st?
```kql
AuthenticationEvents
| where timestamp > endofday(todatetime("2024-01-31")) and username =~ "bashmelly"
```

###### How many other accounts did that IP log into?
```kql
AuthenticationEvents
| where src_ip == "143.38.175.105"
```

###### How many IPs logged in to all 8 devices where the attacker ran systeminfo?
```kql
let hosts = ProcessEvents
| where process_commandline has "systeminfo"
| distinct hostname;
AuthenticationEvents
| where hostname in (hosts)
| summarize dcount(hostname) by src_ip
| order by dcount_hostname desc
```

###### What is the role of the employee who this IP address belongs to?
```kql
Employees
| where ip_addr == "10.10.0.138"
```

###### How many successful logins were made from this IP?
```kql
AuthenticationEvents
| where src_ip == "10.10.0.138" and result =~ "Successful Login"
```

###### What is the hostname of the server the attackers logged into?
```kql
AuthenticationEvents
| where src_ip == "10.10.0.138" and result =~ "Successful Login" and hostname contains "server"
```