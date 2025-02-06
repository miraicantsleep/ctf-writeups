#!/bin/bash

content=$(<flag.txt)

for i in {1..5}; do
    content=$(echo -n "$content" | base64)
done

finalContent=$content

for ((i=0; i<${#finalContent}; i++)); do
    char="${finalContent:$i:1}"
    echo -n "$char"
    sleep 0.01
done

echo -e "\nDone"
