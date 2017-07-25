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
chkauditrules=`grep actions /etc/audit/audit.rules`
auditrules='-w /var/log/sudo.log -p wa -k actions '

if [ -n "$chkauditrules" -o "$chkauditrules" == "$auditrules" ]
then 
	echo $auditrules
else
	echo "Audit rules empty"
fi

#6.2.1.19
chkmodules=`grep modules /etc/audit/audit.rules`



#6.2.1.20
chkimmute=`grep "^-e 2" /etc/audit/audit.rules`



