# SetDNSInfo
Set DNS Info
	Reconfigures the DNS Server(s) on a network interface on specified computers in 
	Microsoft Active Directory. The computer accounts processed are filtered by IPEnabled 
	and DHCP Disabled. Only computers using a Static IP Address are processed.
	
	Creates a text file named DNSChangeStatus.txt, by default, in the folder where the script 
	is run.
	
	Optionally, can specify the output folder.
	
	The user running the script must be a member of Domain Admins.
	
	The script has been tested with PowerShell versions 3, 4, 5, and 5.1.
	The script has been tested with Microsoft Windows Server 2008 R2 (with PowerShell V3), 
	2012, 2012 R2, 2016, 2019 and Windows 10.
