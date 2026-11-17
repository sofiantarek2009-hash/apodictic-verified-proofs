terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.40"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.28"
    }
  }
}

variable "region" {
  default = "us-east-1"
}

variable "node_count" {
  description = "Target node count for the distributed verification cluster"
  default     = 10000
}

resource "aws_eks_cluster" "noesis_cluster" {
  name     = "noesis-10k-verification-mesh"
  role_arn = "arn:aws:iam::123456789012:role/NoesisClusterRole"

  vpc_config {
    subnet_ids = ["subnet-0a1b2c3d4e5f", "subnet-0b2c3d4e5f6a"]
  }
}

resource "aws_eks_node_group" "noesis_baremetal_pool" {
  cluster_name    = aws_eks_cluster.noesis_cluster.name
  node_group_name = "baremetal-kvm-workers"
  node_role_arn   = "arn:aws:iam::123456789012:role/NoesisNodeRole"
  subnet_ids      = ["subnet-0a1b2c3d4e5f", "subnet-0b2c3d4e5f6a"]
  instance_types  = ["c5n.metal", "m5zn.metal"]

  scaling_config {
    desired_size = 10000
    max_size     = 12000
    min_size     = 1000
  }
}
