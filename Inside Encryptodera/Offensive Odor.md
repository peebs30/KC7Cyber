###### What is Barry's role at the company?
```kql
Employees
| where name =~ "Barry Shmelly"
|project role
```

###### What is Barry's email address?
```kql
Employees
| where name =~ "Barry Shmelly"
|project email_addr
```

###### What was the subject of the interesting email (the one on January 16th) that Barry sent?
```kql
Email
| where timestamp between (startofday(todatetime("2024-01-16")) .. endofday(todatetime("2024-01-16")))
| where sender =~ "barry_shmelly@encryptoderafinancial.com"
```

###### **What was the role of the employees that received Barry's email?**
```kql
Email
| where subject =~ "I'm not coming in today. I'm sick of this place. We're all getting laid off anyway."
| distinct recipient
| join Employees on $left.recipient == $right.email_addr
| project role
```

###### What was the role of the recipient of that email?
```kql
Email
| where subject =~ "YOU ARE A GREEDY PIG!!!! WHAT IS WRONG WITH YOU?????"
| distinct recipient
| join Employees on $left.recipient == $right.email_addr
| project role
```

###### What's Barry's IP address? (Paste the full IP address )
```kql
Employees
| where name =~ "Barry Shmelly"
|project ip_addr
```

###### What was the complete URL that Barry was browsing on his computer regarding Cybersecurity Insiders on the afternoon of December 26th?(Paste the full url)
```kql
OutboundNetworkEvents
| where timestamp between (startofday(todatetime("2023-12-26")) .. endofday(todatetime("2023-12-26")))
| where src_ip == "10.10.0.1"
|project url
```

###### What website did he visit first on January 15th? (Paste the full URL)
```kql
OutboundNetworkEvents
| where timestamp between (startofday(todatetime("2024-01-15")) .. endofday(todatetime("2024-01-15")))
| where src_ip == "10.10.0.1"
| top 1 by timestamp asc
```

###### Could you provide the full URL for the website Barry searched for USB Flash Drives?
```kql
OutboundNetworkEvents
| where timestamp between (startofday(todatetime("2024-01-15")) .. endofday(todatetime("2024-01-15")))
| where src_ip == "10.10.0.1"
```

###### What "secret" document on business transactions did Barry download?
```kql
search in (FileCreationEvents) "secret"
```

###### What document (docx) did Barry download about salaries?
```kql
FileCreationEvents
| where hostname =~ "IGOY-DESKTOP" and filename endswith "docx"
```

###### What document (zip) did Barry download to get this?
```kql
FileCreationEvents
| where hostname =~ "IGOY-DESKTOP" and filename endswith "zip"
```

###### Do you know the password he used to zip the files?
```kql
ProcessEvents
| where hostname =~ "IGOY-DESKTOP"
```