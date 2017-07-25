#! /bin/bash

#6.2.1.15

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


