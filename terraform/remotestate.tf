data "aws_region" "current" {}

terraform {
  backend "s3" {
    # set by terraform init -backend-config in provision.py
    #bucket         = ""
    #region         = ""
    #dynamodb_table = ""
    key             = "aws-iam-user-tool/terraform.tfstate"
  }
}
