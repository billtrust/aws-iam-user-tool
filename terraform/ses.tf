resource "aws_ses_template" "iamtool_welcome" {
  name    = "iamtool_welcome"
  subject = "Your AWS IAM login credentials"
  html    = "${file("../content/welcome_email_cssinline.html")}"
  text    = "${file("../content/welcome_email.txt")}"
}
