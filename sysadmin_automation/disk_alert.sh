#!/bin/bash
#----------------------------------------------------------
# Disk Usage Alert Script
# Author: Krishnarao
# Purpose: Email alert when disk usage exceeds threshold
# Compatible: AlmaLinux / RHEL / CentOS / Ubuntu
#----------------------------------------------------------

# Configuration
THRESHOLD=90
EMAIL="krishna@exceleron.com"
HOSTNAME=$(hostname)

# Get disk usage (%)
df -H | grep -vE '^Filesystem|tmpfs|cdrom' | awk '{print $5 " " $1}' | while read output; do
  usage=$(echo $output | awk '{print $1}' | sed 's/%//')
  partition=$(echo $output | awk '{print $2}')

  if [ $usage -ge $THRESHOLD ]; then
    SUBJECT="⚠️ Disk Alert on $HOSTNAME - $partition at ${usage}%"
    MESSAGE="Warning: The partition \"$partition\" on server \"$HOSTNAME\" is ${usage}% full.

Please take necessary action to free up space.

Generated at: $(date)"

    echo "$MESSAGE" | mail -s "$SUBJECT" "$EMAIL"
  fi
done
