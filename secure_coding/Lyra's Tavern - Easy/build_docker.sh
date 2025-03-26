#!/bin/bash
docker build -t lyras_tavern .
docker run  --name=lyras_tavern --rm -p 80:3000 -p 445:445 -p 1337:1337 -it lyras_tavern