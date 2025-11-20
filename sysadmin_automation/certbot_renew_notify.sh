#!/bin/bash
#----------------------------------------------------------
# Certbot Renewal Monitor Script
# Author: Krishnarao Patini
# Purpose: Run certbot renewal and email on failure
#----------------------------------------------------------

EMAIL="krishna@exceleron.com"
HOSTNAME=$(hostname)
LOGFILE="/var/log/certbot_renew_notify.log"
DATE=$(date "+%Y-%m-%d %H:%M:%S")

# Run certbot renew
/usr/bin/certbot renew --quiet
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    SUBJECT="⚠️ Certbot Renewal FAILED on $HOSTNAME"
    MESSAGE="Certbot renewal failed on server: $HOSTNAME at $DATE.

Please log in and check:
  /var/log/letsencrypt/letsencrypt.log

Exit Code: $EXIT_CODE

Run manually:
  sudo certbot renew --dry-run

-- Automated Alert
"

    echo "$MESSAGE" | mail -s "$SUBJECT" "$EMAIL"
    echo "$DATE - Renewal failed (exit code $EXIT_CODE)" >> $LOGFILE
else
    echo "$DATE - Renewal successful or not needed" >> $LOGFILE
fi
