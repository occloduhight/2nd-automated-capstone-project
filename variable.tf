variable "cidr" {}
variable "pub_sn1" {}
variable "pub_sn2" {}
variable "prv_sn1" {}
variable "prv_sn2" {}

variable "all_cidr" {
  type = string
}

variable "httpport" {}
variable "httpsport" {}
variable "sshport" {}
variable "mysqlport" {}

variable "db_identifier" {}
variable "dbname" {}

variable "db_cred" {
  description = "Database credentials for RDS instance"
  type = object({
    username = string
    password = string
  })
  sensitive = true
}

variable "redhat_ami" {}
variable "instance_type" {}
variable "domain" {}
