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

data "aws_ssm_parameter" "root" {
  name = "/old/cms/root"
}
data "aws_ssm_parameter" "database" {
  name = "/old/cms/database"
}
data "aws_ssm_parameter" "username" {
  name = "/old/cms/username"
}
data "aws_ssm_parameter" "password" {
  name = "/old/cms/password"
}
data "aws_ssm_parameter" "imdave" {
  name = "/old/cms/imdave"
}

resource "aws_iam_role" "ec2_assume_role" {
  name               = "ec2_assume_role"
  assume_role_policy = <<-EOF
    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Action": "sts:AssumeRole",
          "Principal": {
            "Service": "ec2.amazonaws.com"
          },
          "Effect": "Allow",
          "Sid": ""
        }
      ]
    }
    EOF
}

resource "aws_iam_role_policy" "s3_access_policy" {
  name   = "s3_access_policy"
  role   = aws_iam_role.ec2_assume_role.id
  policy = <<-EOF
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Action": [
          "s3:*"
        ],
        "Effect": "Allow",
        "Resource": ["arn:aws:s3:::old-comp-clinic", "arn:aws:s3:::old-comp-clinic/*"]
      }
    ]
  }
  EOF
}

resource "aws_iam_instance_profile" "allow_s3_profile" {
  name = "allow_s3_profile"
  role = aws_iam_role.ec2_assume_role.name
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
  ami                         = data.aws_ami.amazon-linux-2.id
  instance_type               = "t2.micro"
  subnet_id                   = var.vpn-dept-oregon-dev-private-a
  associate_public_ip_address = false
  key_name                    = aws_key_pair.generated-key.key_name
  vpc_security_group_ids      = [aws_security_group.security_group.id]
  iam_instance_profile        = aws_iam_instance_profile.allow_s3_profile.name
  user_data                   = <<-EOF
    #!/bin/bash
    ##
    sudo yum update -y
    sudo yum upgrade -y
    ##  
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
    ##
    aws s3 cp s3://old-comp-clinic/cmsccdb_prod.sql /home/ec2-user/cmscc.sql
    aws s3 cp s3://old-comp-clinic/cmss.tar /home/ec2-user/php.tar
    ##
    sudo tar -xf /home/ec2-user/php.tar -C /opt
    sudo usermod -a -G apache ec2-user
    sudo chown -R ec2-user:apache /opt/webroot
    sudo chmod 2775 /opt/webroot && find /opt/webroot -type d -exec sudo chmod 2775 {} \;
    sudo find /opt/webroot -type f -exec sudo chmod 0664 {} \;
    ##
    sudo sed -i 's|/var/www/html|/opt/webroot|g' /etc/httpd/conf/httpd.conf
    sudo sed -i 's|/var/www|/opt/webroot|g' /etc/httpd/conf/httpd.conf
    sudo systemctl restart httpd
    ##
    mysql --user=root <<MYSQL
    UPDATE mysql.user SET Password=PASSWORD('${data.aws_ssm_parameter.root.value}') WHERE User='root';
    DELETE FROM mysql.user WHERE User='';
    DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
    DROP DATABASE IF EXISTS test;
    DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
    CREATE DATABASE ${data.aws_ssm_parameter.database.value};
    CREATE USER ${data.aws_ssm_parameter.username.value}@localhost;
    SET PASSWORD FOR ${data.aws_ssm_parameter.username.value}@localhost=PASSWORD('${data.aws_ssm_parameter.password.value}');
    GRANT ALL PRIVILEGES ON ${data.aws_ssm_parameter.database.value}.* TO ${data.aws_ssm_parameter.username.value}@localhost IDENTIFIED BY '${data.aws_ssm_parameter.password.value}';
    FLUSH PRIVILEGES;
    MYSQL
    mysql -u${data.aws_ssm_parameter.username.value} -p${data.aws_ssm_parameter.password.value} ${data.aws_ssm_parameter.database.value} < /home/ec2-user/cmscc.sql
    ##
    MYIP=$(curl http://169.254.169.254/latest/meta-data/local-ipv4)
    sudo cat <<-CNF > /home/ec2-user/cmscc.cnf
    [req]
    default_bits  = 2048
    distinguished_name = req_distinguished_name
    req_extensions = req_ext
    x509_extensions = v3_req
    prompt = no
    [req_distinguished_name]
    countryName = US
    stateOrProvinceName = UTAH
    localityName = Provo
    organizationName = BYU
    organizationalUnitName = OIT
    commonName = cmscc-old.byu.edu
    [req_ext]
    subjectAltName = @alt_names
    [v3_req]
    subjectAltName = @alt_names
    [alt_names]
    IP.1 = $MYIP
    CNF
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 -keyout /home/ec2-user/cmscc.key -out /home/ec2-user/cmscc.crt -config /home/ec2-user/cmscc.cnf
    sudo mv /home/ec2-user/cmscc.crt /etc/pki/tls/certs/
    sudo mv /home/ec2-user/cmscc.key /etc/pki/tls/private/
    sudo sed -i 's|/etc/pki/tls/certs/localhost.crt|/etc/pki/tls/certs/cmscc.crt|g' /etc/httpd/conf.d/ssl.conf
    sudo sed -i 's|/etc/pki/tls/private/localhost.key|/etc/pki/tls/private/cmscc.key|g' /etc/httpd/conf.d/ssl.conf
    ##
    sudo sed -i "s|'DB_HOST', ''|'DB_HOST', '127.0.0.1'|g" /opt/webroot/cms3/inc/database_defines.php
    sudo sed -i "s|'DB_USERNAME', ''|'DB_USERNAME', '${data.aws_ssm_parameter.username.value}'|g" /opt/webroot/cms3/inc/database_defines.php
    sudo sed -i "s|'DB_PASSWORD', ''|'DB_PASSWORD', '${data.aws_ssm_parameter.password.value}'|g" /opt/webroot/cms3/inc/database_defines.php
    sudo sed -i "s|'DB_DATABASE', ''|'DB_DATABASE', '${data.aws_ssm_parameter.database.value}'|g" /opt/webroot/cms3/inc/database_defines.php
    sudo sed -i "s|https://cmscc.byu.edu/cms3/|https://$MYIP/cms3/|g" /opt/webroot/cms3/inc/siteconfig_vars.php
    sudo sed -i "s|https://cmscc.byu.edu/client/|https://$MYIP/client/|g" /opt/webroot/cms3/inc/siteconfig_vars.php
    ##
    sudo systemctl restart httpd
    ##
    sudo echo "update cms_user set password = md5('${data.aws_ssm_parameter.imdave.value}') where user_name = 'imdave';" > /home/ec2-user/pwdhack.sql
    mysql -u${data.aws_ssm_parameter.username.value} -p${data.aws_ssm_parameter.password.value} ${data.aws_ssm_parameter.database.value} < /home/ec2-user/pwdhack.sql
    ##
  EOF
  tags = {
    Name = "kempy Old CMS"
  }
}

output "information" {
  value = <<-EOF

    chmod 400 ${aws_key_pair.generated-key.key_name}.pem
    ssh -i ${aws_key_pair.generated-key.key_name}.pem ec2-user@${aws_instance.old-cms.private_ip}

    mysql -u${data.aws_ssm_parameter.username.value} -p${data.aws_ssm_parameter.password.value}

    https://${aws_instance.old-cms.private_ip}/cms3/user_login.php
    user: imdave
    password: ${data.aws_ssm_parameter.imdave.value}

  EOF
}
