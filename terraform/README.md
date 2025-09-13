## Configure AWS
### 1. export ENVs 
```bash
export AWS_ACCESS_KEY_ID="YOUR_NEW_ACCESS_KEY"
export AWS_SECRET_ACCESS_KEY="YOUR_NEW_SECRET_KEY"
```
or specify in provider config
```bash
provider "aws" {
  access_key = "YOUR_NEW_ACCESS_KEY"
  secret_key = "YOUR_NEW_SECRET_KEY"
  region     = "ap-southeast-1"
}
```
### 2. Create an ssh-key for to login to the aws ubuntu instance
```shell
ssh-keygen -t ed25519 -C <your-email> -f ~/.ssh/my-aws-key
```

### 3. If you need any extra linux packages (e.g `vmstat`), add them to the following file
- `packages.sh`

### 3. run terraform init, plan, apply command
```
terraform init
terraform plan
terraform apply
```

### 4. copy the ip address from the output from terraform plan step 
- assume the ip address is `INSTANCE_PUBLIC_IP`
### 5. Connect to the ubuntu instance
```bash
ssh -i ~/.ssh/my-aws-key ubuntu@INSTANCE_PUBLIC_IP
```