#!/bin/bash
docker rm -f cursed_stale_policy
docker build --tag=cursed_stale_policy . 
docker run -p 1337:8000 --rm --name=cursed_stale_policy -it cursed_stale_policy