# GidsiksFail2BanService

Sick of tons botnets trying to bruteforce your services with open ports on Windows machine?

I recieve about thousand failed attempts to logon on my MSSQLServer and RDP a day, so i made this app.

# Overview
GidsiksFail2BanService is simple .NET implementation of fail2ban functionality for Windows.

It can work as Console App or as a Service, since it edits Firewall - it require to run as Administrator.

It tracks failed attempts to logon and in case some IP address failed more than (by default) 3 times in a minute - 
it gets ban by adding it to BlackList rule in WindowsFirewall FOREVER 
(i think i'll add some time tracking for bans and functionality to unban later)

## Installation
WIP

## How does it work
There is a class Fail2Ban that contains list of IScumableService classes and listens to FailedEnough events they rising and handling events it manages Firewall rule, adding new ip to BlackList (using WindowsFirewallHelper nuget) 

There is a Implementations of IScumableServices, that on their own checks events\logs and manages their own attempts number, rising FailedEnough event when some ip exceeds attempts.

## Contribute
You can contribute easyly implementing IScumableService and adding it to the fail2banServices list in Fail2Ban.cs

## Currently Can
* Create&Edit Windows Firewall rule
* Listen to Windows Events and count failed attempts for MSSQLServer failed Logon
* Console,Debug and EventLog Loging

## TODOs
* config file with configuration for each IScumableService
* sqlite to store ips and other info
* unban functionality
* way to interact with application (currently it just works in background)
* Windows(rdp) Logon 
* FTP logon

