## Linux playground and troubleshooting

### 1. Getting a linux (ubuntu) instance
#### Spin up ubuntu instance locally
```shell
docker build -t my-ubuntu -f Dockerfile
docker run my-ubuntu
```
#### Spin up ubuntu instance in aws
```text
follow the instructions in ./terraform/README.md file
```

### 2. If you want to simulate and practice troubleshoot
```text
follow the instructions in ./troubleshoot/README.md file
```