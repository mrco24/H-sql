# H-sql

go install github.com/tomnomnom/H-sql@latest

cp -r /root/go/bin/H-sql /usr/local/bin

H-sql -m list -l url.txt -p payloads.txt -H headers.txt -v -t 4 -o p.txt
