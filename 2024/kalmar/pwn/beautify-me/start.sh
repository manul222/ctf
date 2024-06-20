docker build -t beautify-me .
docker run -d -p 1337:1337 --name beautify-me beautify-me
echo "usage: nc localhost 1337"