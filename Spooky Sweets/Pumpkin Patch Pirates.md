###### Oh no! A bunch of computers had their wallpapers changed. Your IT was able to grab a copy of one of them, but it seems that it slightly changes each time it's on a computer.

###### Let's search for this file. How many hosts have this file?
```kql
FileCreationEvents
| where filename =~ "spooky.png"
| distinct hostname
| count
```
###### What folder is this file found in?
```kql
FileCreationEvents
| where filename =~ "spooky.png"
| distinct path
```
###### When was the first wallpaper created?
```kql
FileCreationEvents
| where filename =~ "spooky.png"
| top 1 by timestamp asc
```
###### What is the SHA256 of that file?
```kql
FileCreationEvents
| where filename =~ "spooky.png"
| top 1 by timestamp asc
| project sha256
```
###### Let's look at the host where the first wallpaper was created. What is the role of the employee that uses this computer?
```kql
FileCreationEvents
| where filename =~ "spooky.png"
| top 1 by timestamp asc
| project hostname
| join  Employees on hostname
| project role
```
###### The threat actor must have left something behind to show how they set the wallpaper. What time did they set the wallpaper on this host?
```kql
ProcessEvents
| where timestamp > todatetime("2023-10-09T02:00:42Z") and hostname =~ "KQQT-DESKTOP"
```
###### What command did they run to update the host system to the new wallpaper?
```kql
ProcessEvents
| where timestamp > todatetime("2023-10-09T02:00:42Z") and hostname =~ "KQQT-DESKTOP"
```
###### It was reported that around the same time the wallpapers changed, a lot of people got an email about mandatory training they had to do. How long was this video?
```kql
Email
| where subject contains "mandatory"
```
###### All of these training emails were sent to employees with the same role. Which job role received the email?
```kql
Email
| where subject contains "mandatory"
| join Employees on $left.recipient == $right.email_addr
| distinct role
```
###### Let's see if the threat actor reached out to targets via email in the past. How many emails have subject lines with the hacker group's name in them?
```kql
search in (Email) "pumpkin" or "patch" or "pirates"

Email
| where subject contains "pumpkin patch pirates"
```
###### Most of those emails were sent from which email address?
```kql
Email
| where subject contains "pumpkin patch pirates"
| summarize count() by sender
| top 1 by count_
```
###### Which of the links in those emails contains an important file?
```kql
Email
| where subject contains "pumpkin patch pirates" and link contains "important"
```
###### What IP does the domain from that link resolve to?
```kql
Email
| where subject contains "pumpkin patch pirates" and link contains "important"
| extend domain = tostring(parse_url(link).Host)
| distinct domain
| join PassiveDns on domain
| project ip
```
###### When did that IP visit the Spooky Sweets website?
```kql
InboundNetworkEvents
| where src_ip == "141.107.162.16"
| top 1 by timestamp asc
```
###### The activity from Q15 demonstrates which MITRE ATT&CK technique?
```kql
```
###### Hey!! The IT folks said to stop what you're doing and investigate another set of emails they got around the same time wallpapers were changed. Within the link, what is the wisdom they impart?
```kql
```
###### … lets go back to our email investigation. Looking at the phishing emails sent by the adversary, which number will surprise us?
```kql
let senders = Email
| where subject contains "pumpkin patch pirates"
| distinct sender;
let reply_tos = Email
| where subject contains "pumpkin patch pirates"
| distinct reply_to;
Email
| where sender in (senders) or sender in (reply_tos)
```
###### What's the name of the excel document they sent?
```kql
Email
| where subject contains "pumpkin patch pirates"
```
###### Some time after the initial emails they sent follow up emails to gather more information. What domain did the senders come from?
```kql
//?
```
###### What command was used to look at all of the computers within a domain?
```kql
ProcessEvents
| where parent_process_name =~ "cmd.exe"
| summarize by process_commandline
| where not(process_commandline has_any ("Microsoft","DumpIt.exe"))
```
###### When was the first time this command was executed?
```kql
ProcessEvents
| where process_commandline =~ @"net view /all /domain"
| top 1 by timestamp asc
```
###### Who is the user of that host? Provide the full name.
```kql
ProcessEvents
| where process_commandline =~ @"net view /all /domain"
| top 1 by timestamp asc
| project hostname
| join Employees on hostname
| project name
```
###### What command used by the threat actor was used to look for information about services?
```kql
ProcessEvents
| where hostname =~ "TQ3G-DESKTOP" and parent_process_name =~ "cmd.exe"
```
###### It was reported that Carlton Toth had a significant security alert. Look for what the alert is. What file was alerted?
```kql
let inf_host = Employees
| where name =~ "Carlton Toth"
| project hostname;
SecurityAlerts
| where description  has_any (inf_host)
```
###### Let's investigate that file path across all of the hosts. How many other files were found in that directory?
```kql
let dir = FileCreationEvents
| where filename =~ "treat.ps1" and hostname =~ "P7DJ-LAPTOP"
| extend sus_path = tostring(parse_path(path).DirectoryPath)
| project sus_path;
FileCreationEvents
| where path has_any (dir)
| distinct path
```
###### Which file was executed through a network share?
```kql
let dir = FileCreationEvents
| where filename =~ "treat.ps1" and hostname =~ "P7DJ-LAPTOP"
| extend sus_path = tostring(parse_path(path).DirectoryPath)
| project sus_path;
let sus_file = FileCreationEvents
| where path has_any (dir)
| extend file = tostring(parse_path(path).Filename)
| distinct file;
ProcessEvents
| where process_commandline has_any (sus_file)
| distinct process_commandline
```
###### Which executive management role had some of these files on their host?
```kql
let dir = FileCreationEvents
| where filename =~ "treat.ps1" and hostname =~ "P7DJ-LAPTOP"
| extend sus_path = tostring(parse_path(path).DirectoryPath)
| project sus_path;
let sus_file = FileCreationEvents
| where path has_any (dir)
| extend file = tostring(parse_path(path).Filename)
| distinct file;
FileCreationEvents
| where filename in (sus_file)
| distinct hostname
| join Employees on hostname
```
###### How many distinct job roles had these files in that directory?
```kql
let dir = FileCreationEvents
| where filename =~ "treat.ps1" and hostname =~ "P7DJ-LAPTOP"
| extend sus_path = tostring(parse_path(path).DirectoryPath)
| project sus_path;
let sus_file = FileCreationEvents
| where path has_any (dir)
| extend file = tostring(parse_path(path).Filename)
| distinct file;
FileCreationEvents
| where filename in (sus_file)
| distinct hostname
| join Employees on hostname
| distinct role
```
