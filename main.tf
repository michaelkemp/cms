terraform {
  required_version = ">= 0.12.24"
}

provider "aws" {
  version = "~>2.59.0"
  region  = "us-west-2"
}

variable "vpn-dept-oregon-dev" {
  type    = string
  default = "vpc-0d5da450de7b3e1ee"
}

variable "vpn-dept-oregon-dev-private-a" {
  type    = string
  default = "subnet-0a49a0288c57235e1"
}

resource "tls_private_key" "kempy" {
  algorithm = "RSA"
  rsa_bits  = 4096
}
resource "aws_key_pair" "generated-key" {
  key_name   = "kempy-compclinic-key"
  public_key = tls_private_key.kempy.public_key_openssh
}
resource "local_file" "write-key" {
  content  = tls_private_key.kempy.private_key_pem
  filename = "${path.module}/kempy-compclinic-key.pem"
}

resource "aws_security_group" "security_group" {
  name        = "kempy_security_group"
  description = "kempy Security Group for CMS"
  vpc_id      = var.vpn-dept-oregon-dev
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "TCP"
    cidr_blocks = ["10.0.0.0/8"]
  }
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "TCP"
    cidr_blocks = ["10.0.0.0/8"]
  }
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "TCP"
    cidr_blocks = ["10.0.0.0/8"]
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

data "aws_ami" "amazon-linux-2" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
  filter {
    name   = "name"
    values = ["amzn2-ami-hvm*"]
  }
}
resource "aws_instance" "old-cms" {
  ami           = data.aws_ami.amazon-linux-2.id
  instance_type = "t2.micro"
  tags = {
    Name = "kempy Old CMS"
  }
  subnet_id                   = var.vpn-dept-oregon-dev-private-a
  associate_public_ip_address = false
  key_name                    = aws_key_pair.generated-key.key_name
  vpc_security_group_ids      = [aws_security_group.security_group.id]
  user_data                   = <<-EOF
    #!/bin/bash
    sudo yum -y install ntp
    sudo ntpdate pool.ntp.org
    sudo yum -y install httpd
    sudo yum -y install mariadb-server mariadb
    sudo yum -y install php php-mysql php-mbstring php-gd php-xml mod_ssl
    sudo systemctl start ntpd
    sudo systemctl start httpd
    sudo systemctl start mariadb
    sudo systemctl enable ntpd
    sudo systemctl enable httpd
    sudo systemctl enable mariadb
    sudo mkdir /opt/webroot
    echo "<?php echo '<p>Hello World</p>'; ?>" > /opt/webroot/index.php
    sudo usermod -a -G apache ec2-user
    sudo chown -R ec2-user:apache /opt/webroot
    sudo chmod 2775 /opt/webroot && find /opt/webroot -type d -exec sudo chmod 2775 {} \;
    sudo find /opt/webroot -type f -exec sudo chmod 0664 {} \;
    sudo sed -i 's|/var/www/html|/opt/webroot|g' /etc/httpd/conf/httpd.conf
    sudo sed -i 's|/var/www|/opt/webroot|g' /etc/httpd/conf/httpd.conf
    sudo systemctl restart httpd
    mysql --user=root <<MYSQL
    UPDATE mysql.user SET Password=PASSWORD('rootpassword') WHERE User='root';
    DELETE FROM mysql.user WHERE User='';
    DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
    DROP DATABASE IF EXISTS test;
    DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
    CREATE DATABASE compclinicdb;
    CREATE USER ccuser@'localhost';
    SET PASSWORD FOR ccuser@'localhost'=PASSWORD('1BDtIvvXT948ez3p1qu7iIlPkkJj8fVo');
    GRANT ALL PRIVILEGES ON compclinicdb.* TO ccuser@'localhost' IDENTIFIED BY '1BDtIvvXT948ez3p1qu7iIlPkkJj8fVo';
    FLUSH PRIVILEGES;
    MYSQL
    MYIP=$(curl http://169.254.169.254/latest/meta-data/local-ipv4)
    sudo echo $MYIP > /home/ec2-user/test.txt
  EOF
}

output "information" {
  value = <<-EOF

    chmod 400 ${aws_key_pair.generated-key.key_name}.pem
    ssh -i ${aws_key_pair.generated-key.key_name}.pem ec2-user@${aws_instance.old-cms.private_ip}

  EOF
}
