# Setup troubleshoot simulations in cloud (aws) ubuntu instance
### 1. copy the files to linux instance (from local machine)
```bash
scp -i ~/.ssh/my-aws-key terraform/troubleshoot-simulation.sh create_troubleshooting_guides.sh ubuntu@INSTANCE_PUBLIC_IP
```
### 2. ssh into your ubuntu instance
```shell
ssh -i ~/.ssh/my-aws-key ubuntu@INSTANCE_PUBLIC_IP
```

### 3. run the shell files
```shell
sh troubleshoot-simulation.sh
sh create_troubleshooting_guides.sh
```