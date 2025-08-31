## How to use the example
1. Build docker image or setup python environment on your host machine.

    ```bash
    # In the case of using docker
    ./helper.sh build

    # In the case of setting up python environment
    # Assumption: you have already installed python3.
    pip install poetry
    cd docker
    poetry config virtualenvs.create false
    poetry install --no-interaction --no-ansi
    ```

1. Start django application

    ```bash
    # In the case of using docker
    ./helper.sh start
    docker exec -it server.passkey bash
    #
    # In the docker environment
    #
    cd example
    python manage.py makemigrations
    python manage.py migrate
    python manage.py runserver 0.0.0.0:8000

    # In the case of setting up python environment
    cd example
    python manage.py makemigrations
    python manage.py migrate
    python manage.py runsslserver 0.0.0.0:8000
    ```

1. Access your web page.