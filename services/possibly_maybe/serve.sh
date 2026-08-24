#!/bin/sh
#input.bind L ~meta.exec "client.lookatradius 0" "chat.add 0 0 MIN"; meta.exec "client.lookatradius 0.2" "chat.add 0 0 DEFAULT"; meta.exec "client.lookatradius 10" "chat.add 0 0 MAX"
set -f
IFS= read -r line || exit 0
exec timeout -s KILL 12 ./svm $line 2>&1
