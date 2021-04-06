resource "tls_private_key" "this" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "key_tf" {
  key_name   = var.key_name
  public_key = tls_private_key.this.public_key_openssh
  depends_on = [
    tls_private_key.this
  ]
}

resource "local_file" "key_creation" {
  content         = tls_private_key.this.private_key_pem
  filename        = "${var.key_name}.pem"
  file_permission = "0544"
  depends_on = [
    tls_private_key.this
  ]
}

data "template_file" "userdata_win" {
template = <<EOF
<script>
echo "" > _INIT_STARTED_
net user ${var.win_user} /add /y
net user ${var.win_user} ${var.win_password}
net localgroup administrators ${var.win_user} /add
echo "" > _INIT_COMPLETE_
</script>
<persist>false</persist>
EOF
}

# build a instance for each AZ

resource "aws_instance" "win-example" {
  for_each               = var.subnet_id
  ami                    = var.ami_id
  instance_type          = var.instance_type
  key_name               = aws_key_pair.key_tf.key_name
  user_data              = data.template_file.userdata_win.rendered
  vpc_security_group_ids = var.security_group_id
  subnet_id              = each.value
  tags = {
    Name        = var.instance_name
    Environment = var.environment
  }
}