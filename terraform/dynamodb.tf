resource "aws_dynamodb_table" "iamusertool_config" {
  name           = "iamusertool_config"
  read_capacity  = 1
  write_capacity = 1
  hash_key       = "id"

  attribute {
    name = "id"
    type = "S"
  }
}
