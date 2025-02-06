#!/bin/sh

check() {
  echo -e "\e[1;34m[+] Verifying Challenge Integrity\e[0m"
  sha256sum -c sha256sum
}

build_container() {
  echo -e "\e[1;34m[+] Building Challenge Docker Container\e[0m"
  docker build -t localhost/chall-snow_globe --platform linux/amd64 .
}

# Common error on default Ubuntu 24.04:
# 
# initCloneNs():391 mount('/', '/', NULL, MS_REC|MS_PRIVATE, NULL): Permission denied
# Change --user 1337:1337 to --user 0:0 in run_container()
# or
# $ sudo sysctl -w kernel.apparmor_restrict_unprivileged_unconfined=0
# $ sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
# and then restore them back when finished

run_container() {
  docker volume create --driver local --opt type=tmpfs --opt device=tmpfs --opt o=size=16M,rw store-snow_globe
  docker network create --driver bridge --internal network_snow_globe
  docker run --name chall-snow_globe --read-only --network network_snow_globe --mount source=store-snow_globe,destination=/tmp --rm -it -d localhost/chall-snow_globe

  CONTAINER_IP="$(docker inspect chall-snow_globe --format '{{ .NetworkSettings.Networks.network_snow_globe.IPAddress }}')"
  echo -e "\e[1;34m[+] Running Challenge Docker Container on http://${CONTAINER_IP}:1337\e[0m"

  docker attach chall-snow_globe
}

kill_container() {
	docker ps --filter "name=chall-snow_globe" --format "{{.ID}}" \
		| tr '\n' ' ' \
		| xargs docker stop -t 0 \
		|| true
	docker network rm network_snow_globe
	docker volume rm store-snow_globe
}

case "${1}" in
  "check")
    check
    ;;
  "build")
    build_container
    ;;
  "run")
    run_container
    ;;
  "kill")
    kill_container
    ;;
  *)
    check
    build_container
    run_container
    ;;
esac
