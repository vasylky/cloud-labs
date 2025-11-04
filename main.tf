provider "aws" {
  region = "eu-central-1"
}

resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
}

resource "aws_subnet" "public_a" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "eu-central-1a"
  map_public_ip_on_launch = true
}

resource "aws_subnet" "private_a" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "eu-central-1a"
}

resource "aws_internet_gateway" "gw" {
  vpc_id = aws_vpc.main.id
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
}

resource "aws_route" "public_internet_access" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.gw.id
}

resource "aws_route_table_association" "public_a" {
  subnet_id      = aws_subnet.public_a.id
  route_table_id = aws_route_table.public.id
}

resource "aws_security_group" "alb_sg" {
  vpc_id = aws_vpc.main.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "ecs_sg" {
  vpc_id = aws_vpc.main.id

  ingress {
    from_port       = 5003
    to_port         = 5003
    protocol        = "tcp"
    security_groups = [aws_security_group.alb_sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "rds_sg" {
  vpc_id = aws_vpc.main.id

  ingress {
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.ecs_sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_subnet_group" "rds" {
  name       = "rds-subnet-group"
  subnet_ids = [aws_subnet.private_a.id]
}

resource "aws_db_instance" "mysql" {
  identifier           = "myapp-db"
  engine               = "mysql"
  instance_class       = "db.t3.micro"
  allocated_storage    = 20
  username             = "admin"
  password             = "SuperSecret123"
  db_subnet_group_name = aws_db_subnet_group.rds.name
  vpc_security_group_ids = [aws_security_group.rds_sg.id]
  skip_final_snapshot  = true
}

resource "aws_ecs_cluster" "main" {
  name = "flask-cluster"
}

resource "aws_ecr_repository" "api" {
  name = "flask-api"
}

resource "aws_lb" "alb" {
  name               = "flask-alb"
  load_balancer_type = "application"
  subnets            = [aws_subnet.public_a.id]
  security_groups    = [aws_security_group.alb_sg.id]
}

resource "aws_lb_target_group" "api" {
  name     = "flask-tg"
  port     = 5003
  protocol = "HTTP"
  vpc_id   = aws_vpc.main.id
  target_type = "ip"
}

resource "aws_lb_listener" "front_end" {
  load_balancer_arn = aws_lb.alb.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.api.arn
  }
}

resource "aws_ecs_task_definition" "api" {
  family                   = "flask-api"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "256"
  memory                   = "512"

  container_definitions = jsonencode([
    {
      name  = "flask-api"
      image = "${aws_ecr_repository.api.repository_url}:latest"
      portMappings = [
        {
          containerPort = 5003
          hostPort      = 5003
        }
      ]
      environment = [
        {
          name  = "DB_HOST"
          value = aws_db_instance.mysql.address
        },
        {
          name  = "DB_USER"
          value = "admin"
        },
        {
          name  = "DB_PASS"
          value = "SuperSecret123"
        }
      ]
    }
  ])
}

resource "aws_ecs_service" "api" {
  name            = "flask-api-service"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.api.arn
  desired_count   = 2
  launch_type     = "FARGATE"

  network_configuration {
    subnets         = [aws_subnet.private_a.id]
    security_groups = [aws_security_group.ecs_sg.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.api.arn
    container_name   = "flask-api"
    container_port   = 5003
  }

  depends_on = [aws_lb_listener.front_end]
}
