#! /usr/bin/env bash
instance="$1"
if [ "X${instance}" == "X" ]; then
  echo "usage: $0 instance
  exit 1
fi
cp -i 89guac.ldif /etc/dirsrv/slapd-${instance}/schema/
# stop-dirsrv ${instance}
# start-dirsrv ${instance}
