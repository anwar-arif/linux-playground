terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.16"
    }
  }
  required_version = ">= 1.2.0"
}

provider "aws" {
  region = "ap-southeast-1"
}

resource "aws_key_pair" "my-key-pair" {
  key_name   = "my-key-pair"
  public_key = file("~/.ssh/my-aws-key.pub")
}

resource "aws_security_group" "allow_ssh" {
  name = "allow_ssh"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# data "aws_ami" "ubuntu" {
#   most_recent = true

#   filter {
#     name   = "name"
#     values = ["ubuntu/images/hvm-ssd/*-24.04-*"]
#   }

#   filter {
#     name = "architecture"
#     values = ["x86_64"]
#   }

#   filter {
#     name   = "root-device-type"
#     values = ["ebs"]
#   }

#   filter {
#     name   = "virtualization-type"
#     values = ["hvm"]
#   }

#   owners = ["099720109477"] # Canonical
# }

resource "aws_instance" "my-ubuntu" {
  # ami             = data.aws_ami.ubuntu.id
  ami = "ami-06650ca7ed78ff6fa"
  instance_type   = "t2.micro"
  key_name        = aws_key_pair.my-key-pair.key_name
  security_groups = [aws_security_group.allow_ssh.name]

  user_data = file("packages.sh")

  tags = {
    Name = "MyUbuntu"
  }
}

output "instance_public_ip" {
  value = aws_instance.my-ubuntu.public_ip
}
