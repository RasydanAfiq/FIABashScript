#! /bin/bash

#6.2.1.15 Collect Successful File System Mounts
bit64mountb64=`grep "\-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" /etc/audit/audit.rules`
bit64mountb32=`grep "\-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" /etc/audit/audit.rules`
bit32mountb32=`grep "\-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" /etc/audit/audit.rules`

if [ -z "$bit64mountb64" -o -z "$bit64mountb32" -o -z "$bit32mountb32" ]
then
	echo "FAIL - To determine filesystem mounts" 
else
	echo "PASS - To determine filesystem mounts"
fi

#6.2.1.16 Collect File Delection Events by User
bit64delb64=`grep "\-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" /etc/audit/audit.rules`
bit64delb32=`grep "\-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" /etc/audit/audit.rules`
bit32delb32=`grep "\-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" /etc/audit/audit.rules`

if [ -z "$bit64delb64" -o -z "$bit64delb32" -o -z "$bit32delb32" ]
then
	echo "FAIL - To determine the file delection event by user"
else
	echo "PASS - To determine the file delection event by user"
fi

#6.2.1.17 Collect Changes to System Administration Scope
chkscope=`grep scope /etc/audit/audit.rules`
sudoers='-w /etc/sudoers -p wa -k scope'

if [ -z "$chkscope" -o "$chkscope" != "$sudoers" ]
then
	echo "FAIL - To unauthorize change to scope of system administrator activity"
else
	echo "PASS - To unauthorize change to scope of system administrator activity"
fi

#6.2.1.18 
chkadminrules=`grep actions /etc/audit/audit.rules`
adminrules='-w /var/log/sudo.log -p wa -k actions'

if [ -z "$chkadminrules" -o "$chkadminrules" != "$adminrules" ]
then 
	echo "FAILED - Administrator activity not recorded"
else
	echo "PASSED - Administrator activity recorded"
fi

#6.2.1.19
chkmod1=`grep "\-w /sbin/insmod -p x -k modules" /etc/audit/audit.rules`
chkmod2=`grep "\-w /sbin/rmmod -p x -k modules" /etc/audit/audit.rules`
chkmod3=`grep "\-w /sbin/modprobe -p x -k modules" /etc/audit/audit.rules`
chkmod4=`grep "\-a always,exit -F arch=b64 -S init_module -S delete_module -k modules" /etc/audit/audit.rules`

if [ -z "$chkmod1" -o -z "$chkmod2" -o -z "$chkmod3" -o -z "$chkmod4" ]
then
	echo "FAILED - Kernel module not recorded"
else
	echo "PASSED - Kernel module recorded"
fi

#6.2.1.20
chkimmute=`grep "^-e 2" /etc/audit/audit.rules`
immute='-e 2'

if [ -z "$chkimmute" -o "$chkimmute" != "$immute" ]
then
	echo "FAILED - Audit configuration is not immutable"
else
	echo "PASSED - Audit configuration immutable"
fi

#6.2.1.21
chkrotate1=`grep "/var/log/messages" /etc/logrotate.d/syslog`
chkrotate2=`grep "/var/log/secure" /etc/logrotate.d/syslog`
chkrotate3=`grep "/var/log/maillog" /etc/logrotate.d/syslog`
chkrotate4=`grep "/var/log/spooler" /etc/logrotate.d/syslog`
chkrotate5=`grep "/var/log/boot.log" /etc/logrotate.d/syslog`
chkrotate6=`grep "/var/log/cron" /etc/logrotate.d/syslog`

if [ -z "chkrotate1" -o -z "$chkrotate2" -o -z "$chkrotate3" -o -z "$chkrotate4" -o -z "$chkrotate5" -o -z "$chkrotate6" ]
then
	echo "FAILED - System logs not rotated"
else
	echo "PASSED - System logs recorded"
fi
