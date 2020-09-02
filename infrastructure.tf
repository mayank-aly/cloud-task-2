provider "aws" {
  region  = "ap-south-1"
  profile = "mayank"
}


#creating_security_groups
resource "aws_security_group" "firewall" {
  name        = "firewall"
  description = "Allow TLS inbound traffic"


  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "SSH"
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


  tags = {
    Name = "ingress_http_ssh"
  }
}


#creating_keys
resource "tls_private_key" "redhatkey" {
  algorithm = "RSA"
  rsa_bits = 4096
}
resource "aws_key_pair" "redhatkey" {
  key_name   = "redhatkey"
  public_key = tls_private_key.redhatkey.public_key_openssh
}
resource "local_file" "redhatkey" {
  content = tls_private_key.redhatkey.private_key_pem
  filename = "/root/terraform/redhatkey.pem"
}


#launching_instances
resource "aws_instance" "web" {
  depends_on = [
    tls_private_key.redhatkey,
    aws_key_pair.redhatkey,
    local_file.redhatkey,
    aws_security_group.firewall,
  ]
  ami           = "ami-0447a12f28fddb066"
  instance_type = "t2.micro"
  key_name = "redhatkey"
  security_groups = [ "firewall" ]
  connection {
   type     = "ssh"
   user     = "ec2-user"
   private_key = tls_private_key.redhatkey.private_key_pem
   host     = aws_instance.web.public_ip
 }


 provisioner "remote-exec" {
   inline = [
     "sudo yum install httpd  php git -y",
     "sudo systemctl restart httpd",
     "sudo systemctl enable httpd",
   ]
 }
  tags = {
    Name = "TestInfra"
   }
}


#creating_efs_storage
resource "aws_efs_file_system" "foo" {
  creation_token = "my-product"


  tags = {
    Name = "MyProduct"
  }
}


#Creating_Mount_Target
resource "aws_vpc" "efs-vpc" {
  cidr_block = "10.0.0.0/16"
}


resource "aws_subnet" "efs-sub" {
  depends_on = [aws_vpc.efs-vpc]
  vpc_id            = aws_vpc.efs-vpc.id
  availability_zone = "ap-south-1a"
  cidr_block        = "10.0.1.0/24"
}


resource "aws_efs_mount_target" "target" {
    depends_on = [aws_subnet.efs-sub]
  file_system_id = aws_efs_file_system.foo.id
  subnet_id      = aws_subnet.efs-sub.id
}


#mount_efs_mountTarget


resource "null_resource" "mount_vol" {
  depends_on = [
    aws_efs_mount_target.target,
  ]
  connection {
    type     = "ssh"
    user     = "ec2-user"
    private_key = tls_private_key.redhatkey.private_key_pem
    host     = aws_instance.web.public_ip
   }
  provisioner "remote-exec" {
      inline = [
        #"sudo mkfs.ext4  ${aws_efs_mount_target..target.mount_target_dns_name}",
        "sudo mount  ${aws_efs_mount_target.target.mount_target_dns_name}  /var/www/html",
        "sudo rm -rf /var/www/html/*",
        "sudo git clone https://github.com/iam-ghost/terra_task.git /var/www/html/"
        ]
      }
}






#creating S3 bucket:
resource "aws_s3_bucket" "terraimages" {
  depends_on = [
      aws_instance.web
  ]


  bucket = "ghostcode00"
  #region = "ap-south-1"
  acl    = "public-read"
  force_destroy = true
  tags = {
    Name        = "infrabucket1900"
    Environment = "Dev"
  }


  provisioner "local-exec" {
    command = "git clone https://github.com/iam-ghost/terra_task/ infra/ "
    }
  
}




#Documenting_policy_for_s3
data "aws_iam_policy_document" "s3_bucket_policy" {
  statement {
    actions = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.terraimages.arn}/*"]


    principals {
      type = "AWS"
      identifiers = [aws_cloudfront_origin_access_identity.origin_access_identity.iam_arn]
    }
  }


  statement {
    actions = ["s3:ListBucket"]
    resources = [aws_s3_bucket.terraimages.arn]


    principals {
      type = "AWS"
      identifiers = [aws_cloudfront_origin_access_identity.origin_access_identity.iam_arn]
    }


  }
}


#creating bucket policy
resource "aws_s3_bucket_policy" "s3BucketPolicy" {
  depends_on = [
        aws_s3_bucket.terraimages,
    ]
  bucket = aws_s3_bucket.terraimages.id
  policy = data.aws_iam_policy_document.s3_bucket_policy.json
}


#Uploading_image_to_bucket:
resource "aws_s3_bucket_object" "objectimg" {
 depends_on = [
      aws_s3_bucket.terraimages
    ]
  bucket = "ghostcode00"
  key    = "1.png"
  acl    = "public-read"
  source = "infra/images/1.png"
}
  locals {
    s3_origin_id = "myS3Origin"
    }


#creating CloudFront distribution:
resource "aws_cloudfront_distribution" "s3_distribution" {
  depends_on = [
    aws_s3_bucket.terraimages,
  ]
  origin {
    domain_name = aws_s3_bucket.terraimages.bucket_domain_name
    origin_id   = local.s3_origin_id


  s3_origin_config {
    origin_access_identity = aws_cloudfront_origin_access_identity.origin_access_identity.cloudfront_access_identity_path
  }
  }



  enabled             = true
  is_ipv6_enabled     = true


  default_cache_behavior  {
    allowed_methods  = ["GET", "HEAD" , "DELETE" , "OPTIONS" ,  "PATCH" , "POST", "PUT" ]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = local.s3_origin_id


    forwarded_values {
      query_string = false
      headers      = ["Origin"]


      cookies {
        forward = "none"
      }
    }


    viewer_protocol_policy = "allow-all"
    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
  }



  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }


  viewer_certificate {
    cloudfront_default_certificate = true




  }
}




#access_identity_for_cloudfront
resource "aws_cloudfront_origin_access_identity" "origin_access_identity" {
  comment = "Some comment"
}
output "cloudfront-origin" {
  value = "aws_cloudfront_origin_access_identity.origin_access_identity.cloudfront_access_identity_path"
}



#Updating_code_with_cloudfront_domain
resource "null_resource" "portal" {
  depends_on =[ aws_cloudfront_distribution.s3_distribution,aws_instance.web,aws_efs_mount_target.target ]
    connection {
      type = "ssh"
      user = "ec2-user"
      host = aws_instance.web.public_ip
      port = 22
      private_key = tls_private_key.redhatkey.private_key_pem
    }


  provisioner "remote-exec" {
    inline = [
      "sudo su <<EOF",
      "echo \"<img src = 'http://${aws_cloudfront_distribution.s3_distribution.domain_name}/${aws_s3_bucket_object.objectimg.key}' style='width:128px;height:128px;'>\" >> /var/www/html/index.html",
      "EOF",
      "sudo systemctl restart httpd"
     ]
 }
}



resource "null_resource" "launch_portal"  {
  depends_on = [
    null_resource.portal,
  ]
  provisioner "local-exec" {
      command = "chrome  ${aws_instance.web.public_ip}"
    }
}



output "cloudfront_domain" {
  value = aws_cloudfront_distribution.s3_distribution.domain_name
}


output "bucket_id" {
  value = aws_s3_bucket.terraimages.id
}



output "aws_instance_ip" {
  value = aws_instance.web.public_ip
}
