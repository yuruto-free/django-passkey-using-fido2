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

  migrate
    Execute database migration

  help | -h
    Show this message
_EOF_
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

    migrate )
      apps=$(find django/app -type f | grep -oP "(?<=/)([a-zA-Z]+)(?=/apps.py$)" | tr '\n' ' ')
      commands="python manage.py makemigrations ${apps}; python manage.py migrate"
      docker compose run --rm server bash -c "${commands}"

      shift
      ;;

    * )
      shift
      ;;
  esac
done