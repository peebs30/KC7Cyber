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