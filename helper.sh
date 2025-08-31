#!/bin/bash

function Usage() {
cat <<- _EOF_
Usage: $0 command

Enabled commands:
  build
    Build docker image based on `Dockerfile`

  start
    Start all containers

  stop
    Stop all containers

  restart
    Restart all containers

  down
    Destroy all containers

  ps
    Show the running containers

  logs
    Show logs of each container

  help | -h
    Show this message
_EOF_
}

function clean_up() {
  # Delete disabled containers
  docker ps -a | grep Exited | awk '{print $1;}' | xargs -I{} docker rm -f {}
  # Delete disabled images
  docker images | grep none | awk '{print $3;}' | xargs -I{} docker rmi {}
  # Delete temporary volumes
  docker volume ls | grep -oP "\s+[0-9a-f]+$" | awk '{print $1}' | xargs -I{} docker volume rm {}
}

# ================
# = main routine =
# ================
if [ $# -eq 0 ]; then
  Usage
  exit 0
fi

while [ -n "$1" ]; do
  case "$1" in
    help | -h )
      Usage

      shift
      ;;

    build )
      docker compose build --build-arg UID="$(id -u)" --build-arg GID="$(id -g)"
      clean_up

      shift
      ;;

     start )
      docker compose up -d

      shift
      ;;

    stop | restart | down )
      docker compose $1

      shift
      ;;

    ps )
      docker compose ps --format 'table {{ .Service }}\t{{ .Status }}\t{{ .Ports }}'

      shift
      ;;

    logs )
      docker compose logs -t | sort -t "|" -k 1,+2d

      shift
      ;;

    * )
      shift
      ;;
  esac
done