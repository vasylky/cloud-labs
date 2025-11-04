#!/bin/sh


URL=${1?"Usage: $0 URL CONCURRENCY RPS DURATION"}
CONCURRENCY=${2:-5}
RPS=${3:-0}
DURATION=${4:-60}


worker() {
  while :; do
    curl -s -o /dev/null -w "%{http_code} %{time_total}\n" --max-time 5 "$URL"
    
    if [ "$RPS" -gt 0 ]; then
      
      per=$(( RPS / CONCURRENCY ))
      if [ "$per" -lt 1 ]; then
        
        sleep_time=$(awk "BEGIN {printf \"%.3f\", 1/$RPS}")
        sleep "$sleep_time"
      else
        sleep_time=$(awk "BEGIN {printf \"%.3f\", 1/$per}")
        sleep "$sleep_time"
      fi
    fi
  done
}


end_time=$(( $(date +%s) + DURATION ))
i=0
echo "[loadgen] start target=$URL concurrency=$CONCURRENCY rps=$RPS duration=${DURATION}s"

while [ $i -lt $CONCURRENCY ]; do
  worker "$i" &
  pids="$pids $!"
  i=$((i+1))
done


while [ $(date +%s) -lt $end_time ]; do
  sleep 1
done

echo "[loadgen] time up, killing workers"
for pid in $pids; do
  kill "$pid" 2>/dev/null || true
done
wait 2>/dev/null || true
echo "[loadgen] finished"
