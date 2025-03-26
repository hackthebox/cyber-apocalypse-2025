#!/bin/bash
docker build -t stoneforges_domain .
docker run  --name=stoneforges_domain --rm -p 80:3000 -p 445:445 -p 1337:1337 -p 1338:1338 -it stoneforges_domain
