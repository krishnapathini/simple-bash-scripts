
# XXX XXX XXX  THIS IS A NEW FILE XXX XXX XXX

#!/bin/bash 

#
# cpu_utilisation.sh
#
# Developed by krishna Patini <krishna@exceleron.com>
# Copyright (c) 2023 Exceleron Inc
# Licensed under terms of GNU General Public License.
# All rights reserved.
#
# Changelog:
# 2023-04-11 - created
#

# $Platon$
PATHS="/"
HOSTNAME="$(hostname)"
CRITICAL=90
WARNING=80
CRITICAL_MAIL="krishna@exceleron.com"
WARNING_MAIL="krishna@exceleron.com"
mkdir -p /var/log/cpu_alerts
LOGFILE=/var/log/cpu_alerts/cpuusage-`date +%h%d%y`.log
touch=$LOGFILE

for path in $PATHS
do
	CPULOAD=`top -b -n 2 -d1 | grep "Cpu(s)" | tail -n1 | awk '{print $2}' | awk -F. '{print $1}'`
if [ -n $WARNING -a -n $CRITICAL ];	then
	if [ "$CPULOAD" -ge "$WARNING" -a "$CPULOAD" -lt "$CRITICAL" ]; then
		echo "`date "+%F %H:%M:%S"`  WARNING - $CPULOAD on host $HOSTNAME" >> $LOGFILE
		echo "Warning Cpuload $CPULOAD on Host $HOSTNAME" | mail -s "CPUload Warning on $HOSTNAME" $WARNING_MAIL
		exit 1
	elif [ "$CPULOAD" -ge "$CRITICAL" ]; then
		echo "`date "+%F %H:%M:%S"` CRITICAL - $CPULOAD on host $HOSTNAME" >> $LOGFILE
		echo "CRITICAL  CPUload $CPULOAD on Host $HOSTNAME" | mail -s "CPUload is Pretty High on $HOSTNAME" $CRITICAL_MAIL
		exit 2
	else
		echo "`date "+%F %H:%M:%S"` CPUload is under thresold - $CPULOAD on $HOSTNAME" >> $LOGFILE
		exit 0
	fi
fi
done
