locals {
  wordpress_script = <<-EOF
#!/bin/bash
set -e

# Update and upgrade system
sudo yum update -y
sudo yum upgrade -y

# Install Apache, PHP, MySQL packages
sudo yum install -y httpd php php-mysqlnd wget unzip

# Enable and start Apache
sudo systemctl enable httpd
sudo systemctl start httpd

# Set hostname
sudo hostnamectl set-hostname webserver

# Download and install AWS CLI v2
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install

# Create a test file for ALB health check
echo "Health check OK" > /var/www/html/indextest.html

# Download and install WordPress
cd /tmp
wget https://wordpress.org/wordpress-6.3.1.tar.gz
tar -xzf wordpress-6.3.1.tar.gz
sudo cp -r wordpress/* /var/www/html/
sudo rm -rf wordpress wordpress-6.3.1.tar.gz

# Set ownership and permissions
sudo chown -R apache:apache /var/www/html
sudo chmod -R 755 /var/www/html

# Configure wp-config.php with DB credentials from Secrets Manager
DB_USER="${local.db_cred.username}"
DB_PASSWORD="${local.db_cred.password}"
DB_NAME="${var.dbname}"
DB_HOST="$(aws rds describe-db-instances --db-instance-identifier ${var.db_identifier} --query 'DBInstances[0].Endpoint.Address' --output text)"

cd /var/www/html
mv wp-config-sample.php wp-config.php
sed -i "s/database_name_here/${var.dbname}/" wp-config.php
sed -i "s/username_here/${local.db_cred.username}/" wp-config.php
sed -i "s/password_here/${local.db_cred.password}/" wp-config.php
sed -i "s/localhost/${local.db_endpoint}/" wp-config.php


# Enable .htaccess overrides
sudo sed -i 's/AllowOverride None/AllowOverride All/' /etc/httpd/conf/httpd.conf

# Configure WordPress rewrite rules for CloudFront
cat <<EOT > /var/www/html/.htaccess
Options +FollowSymlinks
RewriteEngine on
RewriteRule ^wp-content/uploads/(.*)$ https://${data.aws_cloudfront_distribution.cloudfront.domain_name}/wp-content/uploads/\$1 [R=301,NC,L]
# BEGIN WordPress
# END WordPress
EOT

# Sync WordPress files to S3 code bucket
aws s3 sync /var/www/html/ s3://autocap2-code-bucket

# Set up cron jobs to keep files in sync
echo "* * * * * ec2-user /usr/local/bin/aws s3 sync s3://autocap2-code-bucket /var/www/html/" >> /etc/crontab
echo "* * * * * ec2-user /usr/local/bin/aws s3 sync /var/www/html/wp-content/uploads/ s3://autocap2-media" >> /etc/crontab

# Restart Apache
sudo systemctl restart httpd
sudo setenforce 0

EOF
}

# locals {
#   wordpress_script = <<-EOF
 #!/bin/bash

# sudo yum update -y
# sudo yum upgrade -y

# # Start Apache
# systemctl enable httpd
# systemctl start httpd

# #Download and install AWS CLI
# curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
# sudo yum install unzip -y
# unzip awscliv2.zip
# sudo ./aws/install

# #Install Apache, PHP, and MySQL packages
# sudo yum install httpd php php-mysqlnd -y

# cd /var/www/html
# touch indextest.html
# echo "This is a test file" > indextest.html

# #Install wget, download and extract WordPress
# sudo yum install wget -y
# wget https://wordpress.org/wordpress-6.3.1.tar.gz
# tar -xzf wordpress-6.3.1.tar.gz
# cp -r wordpress/* /var/www/html/
# rm -rf wordpress
# rm -rf wordpress-6.3.1.tar.gz

# chmod -R 755 wp-content
# chown -R apache:apache wp-content
# cd /var/www/html && mv wp-config-sample.php wp-config.php

# #Configure the WordPress database connection 
# sed -i "s@define( 'DB_NAME', 'database_name_here' )@define( 'DB_NAME', '${var.dbname}' )@g" /var/www/html/wp-config.php
# sed -i "s@define( 'DB_USER', 'username_here' )@define( 'DB_USER', '${local.db_cred.username}' )@g" /var/www/html/wp-config.php
# sed -i "s@define( 'DB_PASSWORD', 'password_here' )@define( 'DB_PASSWORD', '${local.db_cred.password}' )@g" /var/www/html/wp-config.php
# sed -i "s@define( 'DB_HOST', 'localhost' )@define( 'DB_HOST', '${element(split(":", aws_db_instance.wordpress_db.endpoint), 0)}')@g" /var/www/html/wp-config.php
# sudo sed -i  -e '154aAllowOverride All' -e '154d' /etc/httpd/conf/httpd.conf
# cat <<EOT> /var/www/html/.htaccess
# Options +FollowSymlinks
# RewriteEngine on
# RewriteRule ^wp-content/uploads/(.*)$ https://${data.aws_cloudfront_distribution.cloudfront.domain_name}/wp-content/uploads/$1 [R=301,NC,L]
# # BEGIN WordPress
# # END WordPress
# EOT
# aws s3 cp --recursive /var/www/html/ s3://autocap-code-bucket
# aws s3 sync /var/www/html/ s3://autocap-code-bucket
# echo "* * * * * ec2-user /usr/local/bin/aws s3 sync s3://autocap-code-bucket /var/www/html/" > /etc/crontab
# echo "* * * * * ec2-user /usr/local/bin/aws s3 sync /var/www/html/wp-content/uploads/ s3://autocap-media" >> /etc/crontab

# systemctl restart httpd
# sudo setenforce 0
# sudo hostnamectl set-hostname webserver

# EOF  
# }