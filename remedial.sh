# ! /bin/bash

#6.2.1.15 Collect Successful File System Mounts
bit64mountb64=`grep "\-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" /etc/audit/audit.rules`
bit64mountb32=`grep "\-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" /etc/audit/audit.rules`
bit32mountb32=`grep "\-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" /etc/audit/audit.rules`

if [ -z "$bit64mountb64" ]
then
	echo "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" >> /etc/audit/audit.rules
fi

if [ -z "$bit64mountb32" ]
then
	echo "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" >> /etc/audit/audit.rules
fi

pkill -HUP -P 1 auditd

if [ -z "$bit32mountb32" ]
then
	echo "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" >> /etc/audit/audit.rules
fi

pkill -HUP -P 1 auditd

#2.6.1.16 Collect File Delection Events by User
bit64delb64=`grep "\-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" /etc/audit/audit.rules`
bit64delb32=`grep "\-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" /etc/audit/audit.rules`
bit32delb32=`grep "\-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" /etc/audit/audit.rules`

if [ -z "$bit64delb64" ]
then
	echo "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/audit.rules
fi

if [ -z "$bit64delb32" ]
then
	echo "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/audit.rules
fi

pkill -HUP -P 1 auditd

if [ -z "$bit32delb32" ]
then
	echo "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/audit.rules
fi

pkill -P 1 -HUP auditd

#6.2.1.17 Collect Changes to System Administrator Scope
sudoers=`grep "\-w /etc/sudoers -p wa -k scope" /etc/audit/audit.rules`

if [ -z "$sudoers" ]
then
	echo "-w /etc/sudoers -p wa -k scope" >> /etc/audit/audit.rules
fi
pkill -HUP -P 1 auditd

#6.2.1.18
remauditrules=`grep actions /etc/audit/audit.rules`
auditrules='-w /var/log/sudo.log -p wa -k actions'

if [ -z "$remauditrules" -o "$remauditrules" != "$auditrules" ] 
then
	echo "$auditrules" >> /etc/audit/audit.rules
fi

pkill -HUP -P 1 auditd

#6.2.1.19
remmod1=`grep "\-w /sbin/insmod -p x -k modules" /etc/audit/audit.rules`
remmod2=`grep "\-w /sbin/rmmod -p x -k modules" /etc/audit/audit.rules`
remmod3=`grep "\-w /sbin/modprobe -p x -k modules" /etc/audit/audit.rules`
remmod4=`grep "\-a always,exit -F arch=b64 -S init_module -S delete_module -k modules" /etc/audit/audit.rules`

if [ -z "$remmod1" -o -z "$remmod2" -o -z "$remmod3" -o -z "$remmod4" -o -z "$remmod5" ]
then
	if [ -z "$remmod1" ]
	then
		echo "-w /sbin/insmod -p x -k modules" >> /etc/audit/audit.rules
	fi

	if [ -z "$remmod2" ]
	then	
		echo "-w /sbin/rmmod -p x -k modules" >> /etc/audit/audit.rules
	fi

	if [ -z "$remmod3" ]
	then
		echo "-w /sbin/modprobe -p x -k modules" >> /etc/audit/audit.rules
	fi

	if [ -z "$remmod4" ]
	then
		echo "-a always,exit -F arch=b64 -S init_module -S delete_module -k modules" >> /etc/audit/audit.rules
	fi
fi

#6.2.1.20
remimmute=`grep "^-e 2" /etc/audit/audit.rules`
immute='-e 2'

if [ -z "$remimmute" -o "$remimmute" != "$immute" ]
then
	echo "$immute" >> /etc/audit/audit.rules
fi

#6.2.1.21
remlogrotate=`grep "/var/log" /etc/logrotate.d/syslog`
logrotate='/var/log/messages /var/log/secure /var/log/maillog /var/log/spooler /var/log/boot.log /var/log/cron {'

if [ -z "$remlogrotate" -o "$remlogrotate" != "$logrotate" ]
then
	rotate1=`grep "/var/log/messages" /etc/logrotate.d/syslog`
	rotate2=`grep "/var/log/secure" /etc/logrotate.d/syslog`
	rotate3=`grep "/var/log/maillog" /etc/logrotate.d/syslog`
	rotate4=`grep "/var/log/spooler" /etc/logrotate.d/syslog`
	rotate5=`grep "/var/log/boot.log" /etc/logrotate.d/syslog`
	rotate6=`grep "/var/log/cron" /etc/logrotate.d/syslog`
	
	if [ -z "$rotate1" ]
	then
		echo "/var/log/messages" >> /etc/logrotate.d/syslog
	fi

	if [ -z "$rotate2" ]
	then
		echo "/var/log/secure" >> /etc/logrotate.d/syslog
	fi

	if [ -z "$rotate3" ]
	then 
		echo "/var/log/maillog" >> /etc/logrotate.d/syslog
	fi

	if [ -z "$rotate4" ]
	then
		echo "/var/log/spooler" >> /etc/logrotate.d/syslog
	fi

	if [ -z "$rotate5" ]
	then
		echo "/var/log/boot.log" >> /etc/logrotate.d/syslog
	fi

	if [ -z "$rotate6" ]
	then
		echo "/var/log/cron" //etc/logrotate.d/syslog
	fi
fi
