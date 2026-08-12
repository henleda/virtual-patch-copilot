# Dedicated lab VPC (10.30.0.0/16), one AZ. The external subnet carries both the
# BIG-IP dataplane interface and the Larkspur origin; the mgmt subnet carries the
# BIG-IP management interface (no public inbound — reached via the SSM tunnel).

resource "aws_vpc" "lab" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "${var.project}-vpc"
  }
}

resource "aws_internet_gateway" "lab" {
  vpc_id = aws_vpc.lab.id

  tags = {
    Name = "${var.project}-igw"
  }
}

resource "aws_subnet" "external" {
  vpc_id                  = aws_vpc.lab.id
  cidr_block              = var.external_subnet_cidr
  availability_zone       = var.az
  map_public_ip_on_launch = true # origin gets a public IP for egress (docker pull, SSM) — inbound is still SG-locked

  tags = {
    Name = "${var.project}-external"
  }
}

resource "aws_subnet" "mgmt" {
  vpc_id            = aws_vpc.lab.id
  cidr_block        = var.mgmt_subnet_cidr
  availability_zone = var.az

  tags = {
    Name = "${var.project}-mgmt"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.lab.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.lab.id
  }

  tags = {
    Name = "${var.project}-public-rt"
  }
}

# Both subnets route to the IGW: the origin egresses for docker/SSM, and the BIG-IP
# mgmt EIP (when enabled) egresses for AS3 download / updates.
resource "aws_route_table_association" "external" {
  subnet_id      = aws_subnet.external.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "mgmt" {
  subnet_id      = aws_subnet.mgmt.id
  route_table_id = aws_route_table.public.id
}
