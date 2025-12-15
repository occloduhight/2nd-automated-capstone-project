locals {
  name         = "autocap2"
  email        = "chinweodochi@gmail.com"
  s3_origin_id = aws_s3_bucket.autocap2_media.id
  db_endpoint = aws_db_instance.wordpress_db.endpoint
  db_cred = jsondecode(
    aws_secretsmanager_secret_version.db_cred_version.secret_string
  )
}

#checkov
resource "null_resource" "pre_scan" {
  provisioner "local-exec" {
    command     = "./checkov_scan.sh"
    interpreter = ["bash", "-c"]
  }
  provisioner "local-exec" {
    when    = destroy
    command = "rm -f checkov_output.JSON"
  }
  triggers = {
    always_run = timestamp()
  }
}
# create VPC
resource "aws_vpc" "vpc" {
  cidr_block       = var.cidr
  instance_tenancy = "default"

  tags = {
    Name = "${local.name}-vpc"
  }
}
# create public subnet 1
resource "aws_subnet" "pub_sn1" {
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = var.pub_sn1
  availability_zone = "eu-west-2a"

  tags = {
    Name = "${local.name}-pub_sn1"
  }
}
# create public subnet 2
resource "aws_subnet" "pub_sn2" {
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = var.pub_sn2
  availability_zone = "eu-west-2b"

  tags = {
    Name = "${local.name}-pub_sn2"
  }
}
# create private subnet 1
resource "aws_subnet" "prv_sn1" {
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = var.prv_sn1
  availability_zone = "eu-west-2a"

  tags = {
    Name = "${local.name}-prv_sn1"
  }
}
# create private subnet 2
resource "aws_subnet" "prv_sn2" {
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = var.prv_sn2
  availability_zone = "eu-west-2b"

  tags = {
    Name = "${local.name}-prv_sub2"
  }
}
# create internet gateway
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.vpc.id

  tags = {
    Name = "${local.name}-igw"
  }
}
# create elastic ip
resource "aws_eip" "eip" {
  domain = "vpc"

  tags = {
    Name = "${local.name}-eip"
  }
}
# create nat gateway
resource "aws_nat_gateway" "ngw" {
  allocation_id = aws_eip.eip.id
  subnet_id     = aws_subnet.pub_sn1.id
  depends_on    = [aws_eip.eip]

  tags = {
    Name = "${local.name}-ngw"
  }
}
#  Create route tabble for public subnets
resource "aws_route_table" "pub_rt" {
  vpc_id = aws_vpc.vpc.id
  route {
    cidr_block = var.all_cidr
    gateway_id = aws_internet_gateway.igw.id
  }
  tags = {
    Name = "${local.name}-pub_rt"
  }
}
#  Create route table for private subnets
resource "aws_route_table" "prv_rt" {
  vpc_id = aws_vpc.vpc.id
  route {
    cidr_block = var.all_cidr
    gateway_id = aws_nat_gateway.ngw.id
  }
  tags = {
    Name = "${local.name}-prv_rt"
  }
}
# Creating route table association for public subnet1
resource "aws_route_table_association" "ass_pub_sn1" {
  subnet_id      = aws_subnet.pub_sn1.id
  route_table_id = aws_route_table.pub_rt.id
}
#  Creating route table association for public subnet2
resource "aws_route_table_association" "ass_pub_sn2" {
  subnet_id      = aws_subnet.pub_sn2.id
  route_table_id = aws_route_table.pub_rt.id
}
#  Creating route table association for private_subnet_1
resource "aws_route_table_association" "ass_prv_sn1" {
  subnet_id      = aws_subnet.prv_sn1.id
  route_table_id = aws_route_table.prv_rt.id
}
#  Creating route table association for private_subnet_2
resource "aws_route_table_association" "ass_prv_sn2" {
  subnet_id      = aws_subnet.prv_sn2.id
  route_table_id = aws_route_table.prv_rt.id
}
#frontend security group
resource "aws_security_group" "autocap2_sg" {
  name        = "autocap2-sg"
  description = "Allow inbound traffic"
  vpc_id      = aws_vpc.vpc.id
  ingress {
    description = "HTTP"
    from_port   = var.httpport
    to_port     = var.httpport
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "HTTPS"
    from_port   = var.httpsport
    to_port     = var.httpsport
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "SSH"
    from_port   = var.sshport
    to_port     = var.sshport
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "${local.name}-autocap2-sg"
  }
}
#RDS security group
resource "aws_security_group" "rds_sg" {
  name        = "rds-sg"
  description = "Allow outbound traffic"
  vpc_id      = aws_vpc.vpc.id
  ingress {
    description = "MYSQPORT"
    from_port   = var.mysqlport
    to_port     = var.mysqlport
    protocol    = "tcp"
    # security_groups = [aws_security_group.autocap2_sg.id]
    cidr_blocks = ["${var.pub_sn1}", "${var.pub_sn2}"]
  }
  egress {
    description = "All TRAFFIC"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "${local.name}-rds-sg"
  }
}
#creating keypair RSA key of size 4096 bits
resource "tls_private_key" "key" {
  algorithm = "RSA"
  rsa_bits  = 4096
}
# creating private key
resource "local_file" "key" {
  content         = tls_private_key.key.private_key_pem
  filename        = "autocap-key"
  file_permission = "600"
  depends_on      = [null_resource.pre_scan]
}
# creating public key
resource "aws_key_pair" "key" {
  key_name   = "autocap-pub-key"
  public_key = tls_private_key.key.public_key_openssh
}
# create S3 media bucktet
resource "aws_s3_bucket" "autocap2_media" {
  bucket        = "autocap2-media"
  force_destroy = true
  depends_on    = [null_resource.pre_scan]
  tags = {
    Name = "${local.name}-autocap2-media"
  }
}
resource "aws_s3_bucket_public_access_block" "autocap2_media_pub" {
  bucket                  = aws_s3_bucket.autocap2_media.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_ownership_controls" "autocap2_media_ctrl" {
  bucket = aws_s3_bucket.autocap2_media.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
  depends_on = [aws_s3_bucket_public_access_block.autocap2_media_pub]

}
# Media Bucket policy
resource "aws_s3_bucket_policy" "media_policy" {
  bucket = aws_s3_bucket.autocap2_media.id
  policy = data.aws_iam_policy_document.autocap2_media_policy.json
}

data "aws_iam_policy_document" "autocap2_media_policy" {

  statement {
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    actions = [
      "s3:GetObject",
      "s3:ListBucket",
      "s3:GetObjectVersion"
    ]
    resources = [
      aws_s3_bucket.autocap2_media.arn,
      "${aws_s3_bucket.autocap2_media.arn}/*",
    ]
  }
}
# S3 code Bucket 
resource "aws_s3_bucket" "code_bucket" {
  bucket        = "autocap2-code-bucket"
  depends_on    = [null_resource.pre_scan]
  force_destroy = true

  tags = {
    Name = "${local.name}-code-bucket"
  }
}
# IAM Role for EC2 instances
resource "aws_iam_role" "wordpress_ec2_role" {
  name = "${local.name}-WordPressEC2ServiceRole"

  description = "IAM role assumed by EC2 instances in the WordPress image-sharing app for secure resource access."

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })
  tags = {
    tag-key = "WordPressEC2ServiceRole"
  }
}

# creating media bucket iam policy
resource "aws_iam_policy" "s3_policy" {
  name = "autocap-s3-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = ["s3:*"]
        Resource = "*"
        Effect   = "Allow"
      },
    ]
  })
}
resource "aws_iam_role_policy_attachment" "iam_s3_attachment" {
  role       = aws_iam_role.wordpress_ec2_role.name
  policy_arn = aws_iam_policy.s3_policy.arn
}
#creating iam instance profile
resource "aws_iam_instance_profile" "iam-instance-profile" {
  name = "${local.name}-instance-profile"
  role = aws_iam_role.wordpress_ec2_role.name
}

resource "aws_s3_bucket" "autocap2_log_bucket" {
  bucket        = "autocap2-log-bucket"
  force_destroy = true

  tags = {
    Name = "${local.name}-autocap2-log-bucket"
  }
}
# Use BucketOwnerPreferred
resource "aws_s3_bucket_ownership_controls" "log_bucket_owner" {
  bucket = aws_s3_bucket.autocap2_log_bucket.id

  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_public_access_block" "log_bucket_access_block" {
  bucket                  = aws_s3_bucket.autocap2_log_bucket.id
  block_public_acls       = false
  block_public_policy     = true
  ignore_public_acls      = false
  restrict_public_buckets = false
}

data "aws_iam_policy_document" "log_bucket_access_policy" {
  statement {
    sid    = "AllowELBLogging"
    effect = "Allow"

    actions = [
      "s3:PutObject",
      "s3:PutObjectAcl"
    ]

    resources = [
      "${aws_s3_bucket.autocap2_log_bucket.arn}/*"
    ]

    principals {
      type        = "Service"
      identifiers = ["elasticloadbalancing.amazonaws.com"]
    }
  }
}

resource "aws_s3_bucket_policy" "autocap2_log_bucket_policy" {
  bucket = aws_s3_bucket.autocap2_log_bucket.id
  policy = data.aws_iam_policy_document.log_bucket_access_policy.json
}
# #insert secret manager here
resource "aws_secretsmanager_secret" "db_cred" {
  name        = "db_cred2"
  description = "Database credentials for the WordPress image-sharing application"
}

resource "aws_secretsmanager_secret_version" "db_cred_version" {
  secret_id     = aws_secretsmanager_secret.db_cred.id
  secret_string = jsonencode(var.db_cred)
}

resource "aws_db_subnet_group" "wordpress_db_subnet" {
  name       = "${local.name}-wordpress-db-subnet"
  subnet_ids = [aws_subnet.prv_sn1.id, aws_subnet.prv_sn2.id]

  tags = {
    Name = "${local.name}-wordpress-db-subnet"
  }
}
#Create RDS MySQL Instance
resource "aws_db_instance" "wordpress_db" {
  # identifier             = var.db-identifier
  identifier = var.db_identifier

  db_subnet_group_name    = aws_db_subnet_group.wordpress_db_subnet.name
  vpc_security_group_ids  = [aws_security_group.rds_sg.id]
  allocated_storage       = 20
  max_allocated_storage   = 100 #define storage auto scaling
  db_name                 = var.dbname
  storage_type            = "gp2"
  engine                  = "mysql"
  engine_version          = "5.7"
  instance_class          = "db.t3.micro"
  username                = local.db_cred.username 
  password                = local.db_cred.password 
  parameter_group_name    = "default.mysql5.7"
  skip_final_snapshot     = true  #Whether to skip the final snapshot before deletion
  deletion_protection     = false #Prevent accidental deletion
  publicly_accessible     = false
  backup_retention_period = 3             #days to keep automated RDS backups
  backup_window           = "03:00-04:00"  

  tags = {
    Name = "${local.name}-wordpress_db"
  }
}

resource "aws_ami_from_instance" "asg_ami" {
  name               = "${local.name}-ami"
  source_instance_id = aws_instance.wordpress_server.id
}

resource "time_sleep" "ami-sleep" {
  depends_on      = [aws_instance.wordpress_server]
  create_duration = "360s"
}
#creating aws_cloudfront_distribution
resource "aws_cloudfront_distribution" "s3_distribution" {
  origin {
    domain_name = aws_s3_bucket.autocap2_media.bucket_domain_name
    origin_id   = local.s3_origin_id
  }

  enabled = true

  logging_config {
    include_cookies = false
    bucket          = "autocap2-log-bucket.s3.amazonaws.com"
    prefix          = "cloudfront-log"
  }
  default_cache_behavior {
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = local.s3_origin_id
    
    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }
    }

    viewer_protocol_policy = "allow-all"
    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
  }

  price_class = "PriceClass_All"

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  depends_on = [null_resource.pre_scan]

  tags = {
    Name = "${local.name}-cloudfront"
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }
}
data "aws_cloudfront_distribution" "cloudfront" {
  id = aws_cloudfront_distribution.s3_distribution.id
}

# WordPress EC2 Instance
resource "aws_instance" "wordpress_server" {
  ami                         = var.redhat_ami
  instance_type               = var.instance_type
  depends_on                  = [null_resource.pre_scan]
  associate_public_ip_address = true
  vpc_security_group_ids      = [aws_security_group.autocap2_sg.id, aws_security_group.rds_sg.id]
  subnet_id                   = aws_subnet.pub_sn1.id
  iam_instance_profile        = aws_iam_instance_profile.iam-instance-profile.id
  key_name                    = aws_key_pair.key.id
  user_data                   = local.wordpress_script
  tags = {
    Name = "${local.name}-wordpress_server"
  }
}
#creating ACM certificate
resource "aws_acm_certificate" "acm-cert" {
  domain_name       = "greatminds.sbs"
  validation_method = "DNS"

  tags = {
    Name = "${local.name}-acm-cert"
  }
}
#creating route53 hosted zone
data "aws_route53_zone" "autocap2-zone" {
  name         = var.domain
  private_zone = false
}
#creating A record
resource "aws_route53_record" "autocap2-record" {
  zone_id = data.aws_route53_zone.autocap2-zone.zone_id
  name    = var.domain
  type    = "A"
  alias {
    name                   = aws_lb.lb.dns_name
    zone_id                = aws_lb.lb.zone_id
    evaluate_target_health = true
  }
}
#creating cloudwatch dashboard
resource "aws_cloudwatch_dashboard" "EC2_cloudwatch_dashboard" {
  dashboard_name = "EC2dashboard"

  dashboard_body = jsonencode({
    widgets = [
      {
        type = "metric"
        properties = {
          metrics = [
            ["AWS/EC2", "CPUUtilization", "InstanceId", "${aws_instance.wordpress_server.id}", { "label" : "Average CPU Utilization" }]
          ]
          period  = 300
          region  = "eu-west-2"
          stacked = false
          stat    = "Average"
          title   = "EC2 Average CPUUtilization"
          view    = "timeSeries"
          yAxis = {
            left = {
              label     = "Percentage"
              showUnits = true
            }
          }
        }
      }
    ]
  })
}
# CloudWatch Dashboard for ASG CPU Utilization
resource "aws_cloudwatch_dashboard" "asg_cpu_utilization_dashboard" {
  dashboard_name = "asgcpuutilizationdashboard"

  dashboard_body = jsonencode({
    widgets = [
      {
        type = "metric"
        properties = {
          metrics = [
            ["AWS/EC2", "CPUUtilization", "AutoScalingGroupName", "${aws_autoscaling_group.asg.name}", { "label" : "Average CPU Utilization" }]
          ]
          period  = 300
          view    = "timeSeries"
          stat    = "Average"
          stacked = false
          region  = "eu-west-2"
          title   = "Average CPU Utilization"
          yAxis = {
            left = {
              label     = "Percentage"
              showUnits = true
            }
          }
        }
      },
    ]
  })
}
# CloudWatch Metric Alarm for ASG CPU Utilization
resource "aws_cloudwatch_metric_alarm" "CMA_Autoscaling_Group" {
  alarm_name          = "CMA-ASG-CPU"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 120
  statistic           = "Average"
  threshold           = 50

  alarm_actions = [
    aws_autoscaling_policy.asg-policy.arn,
    aws_sns_topic.server_alert.arn
  ]

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.asg.name
  }
}
#creating sns topic
resource "aws_sns_topic" "server_alert" {
  name            = "server-alert"
  delivery_policy = <<EOF
{
  "http": {
    "defaultHealthyRetryPolicy": {
      "minDelayTarget": 20,
      "maxDelayTarget": 20,
      "numRetries": 3,
      "numMaxDelayRetries": 0,
      "numNoDelayRetries": 0,
      "numMinDelayRetries": 0,
      "backoffFunction": "linear"
    },
    "disableSubscriptionOverrides": false,
    "defaultThrottlePolicy": {
      "maxReceivesPerSecond": 1
    }
  }
}
EOF
}
#creating sns topic subscription
resource "aws_sns_topic_subscription" "autocap2_updates_sqs_target" {
  topic_arn = aws_sns_topic.server_alert.arn
  protocol  = "email"
  endpoint  = local.email
}

# Creating launch template
resource "aws_launch_template" "lnch_lt" {
  name_prefix   = "${local.name}-web_lt"
  image_id      = aws_ami_from_instance.asg_ami.id
  instance_type = var.instance_type
  key_name      = aws_key_pair.key.key_name

  iam_instance_profile {
    name = aws_iam_instance_profile.iam-instance-profile.name
  }

  network_interfaces {
    device_index                = 0
    associate_public_ip_address = true
    security_groups             = [aws_security_group.autocap2_sg.id]
  }

  # user_data = local.wordpress_script
  user_data = base64encode(local.wordpress_script)
}
# resource "aws_ami_from_instance" "asg_ami" {
#   name               = "${local.name}-ami"
#   source_instance_id = aws_instance.wordpress_server[0].id
# }

# resource "aws_ami_from_instance" "asg_ami" {
#   name               = "${local.name}-ami"
#   source_instance_id = aws_instance.wordpress_server.id
# }

# resource "time_sleep" "ami-sleep" {
#   depends_on      = [aws_instance.wordpress_server]
#   create_duration = "360s"
# }
# creating autoscaling group
resource "aws_autoscaling_group" "asg" {
  name                      = "${local.name}-asg"
  max_size                  = 5
  min_size                  = 1
  health_check_grace_period = 300
  health_check_type         = "EC2"
  desired_capacity          = 2
  force_delete              = true

  vpc_zone_identifier = [aws_subnet.pub_sn1.id, aws_subnet.pub_sn2.id]
  target_group_arns   = [aws_lb_target_group.tg.arn]
  launch_template {
    id      = aws_launch_template.lnch_lt.id
    version = "$Latest"
  }

  tag {
    key                 = "Name"
    value               = "ASG"
    propagate_at_launch = true
  }
}

# creating autoscaling policy
resource "aws_autoscaling_policy" "asg-policy" {
  autoscaling_group_name = aws_autoscaling_group.asg.name
  name                   = "${local.name}-asg-policy"
  adjustment_type        = "ChangeInCapacity"
  policy_type            = "TargetTrackingScaling"
  target_tracking_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ASGAverageCPUUtilization"
    }

    target_value = 50.0
  }
}

# creating target group
resource "aws_lb_target_group" "tg" {
  name     = "autocap2-tg"
  port     = var.httpport
  protocol = "HTTP"
  vpc_id   = aws_vpc.vpc.id
  health_check {
    healthy_threshold   = 3
    unhealthy_threshold = 5
    interval            = 60
    port                = 80
    timeout             = 30
    path                = "/indextest.html"
    protocol            = "HTTP"
  }
}

# creating target group listener
resource "aws_lb_target_group_attachment" "tg-attach" {
  target_group_arn = aws_lb_target_group.tg.arn
  target_id        = aws_instance.wordpress_server.id
  port             = var.httpport
}

# ALB Setup with Access Logs-
resource "aws_lb" "lb" {
  name               = "autocap2-lb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.autocap2_sg.id]
  subnets            = [aws_subnet.pub_sn1.id, aws_subnet.pub_sn2.id]

  enable_deletion_protection = false

  access_logs {
    bucket  = aws_s3_bucket.autocap2_log_bucket.id
    prefix  = "AUTOCAP2-LB-LOG"
    enabled = false
  }

  depends_on = [
    aws_s3_bucket_policy.autocap2_log_bucket_policy,
    aws_s3_bucket.autocap2_log_bucket
  ]

  tags = {
    Name = "${local.name}-autocap2-lb"
  }
}

# creating load balancer listener
resource "aws_lb_listener" "lb-listener" {
  load_balancer_arn = aws_lb.lb.arn
  port              = var.httpport
  protocol          = "HTTP"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.tg.arn
  }
}













