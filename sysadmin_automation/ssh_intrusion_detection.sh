#!/bin/bash

LOG="/var/log/secure"
THRESHOLD=5
TIME_WINDOW_MIN=10
EMAIL="krishna@exceleron.com"

# Convert log time (e.g. "Jan 12 14:23:55") to epoch seconds
to_epoch() {
    date --date="$1" +%s 2>/dev/null
}

current_epoch=$(date +%s)
cutoff_epoch=$((current_epoch - TIME_WINDOW_MIN * 60))

# Get only failed ssh attempts in last TIME_WINDOW_MIN minutes
RECENT_FAILS=$(grep "Failed password" "$LOG" | while read -r line; do
    # Extract timestamp (first 3 fields)
    ts=$(echo "$line" | awk '{print $1" "$2" "$3}')
    ts_epoch=$(to_epoch "$ts")

    # Only keep recent entries
    if [[ "$ts_epoch" -ge "$cutoff_epoch" ]]; then
        echo "$line"
    fi
done)

# Extract IPs from recent failures
IPS=$(echo "$RECENT_FAILS" | awk '{print $(NF-3)}' | sort | uniq -c | awk -v t=$THRESHOLD '$1>t{print $2}')

if [[ ! -z "$IPS" ]]; then
    echo -e "Recent SSH brute-force attempts detected in the last $TIME_WINDOW_MIN minutes:\n$IPS" \
        | mail -s "SSH Intrusion Alert (Recent Activity)" "$EMAIL"
fi
