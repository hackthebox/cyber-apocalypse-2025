SET NAME=tales_for_the_brave
docker rm -f forensics_%NAME%
docker build --tag=forensics_%NAME% .
docker run -p 1337:80 --rm --name=forensics_%NAME% --detach forensics_%NAME%
pause