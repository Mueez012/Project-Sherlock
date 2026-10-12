# Declarative settings for an EXISTING GitHub repo: repo options, default branch, branch rules, environments,
# team access. The repo and its develop / QA / main branches must already exist (pushed with git).
#
#   export GITHUB_TOKEN=$(gh auth token)
#   terraform init
#   terraform apply -var-file=team.tfvars
terraform {
  required_version = ">= 1.6"
  required_providers {
    github = {
      source  = "integrations/github"
      version = "~> 6.6"
    }
  }
}

provider "github" {
  owner = var.owner # token is read from the GITHUB_TOKEN environment variable
}

# Adopt the repo you already created instead of creating a new one
import {
  to = github_repository.this
  id = var.repo_name
}

resource "github_repository" "this" {
  name        = var.repo_name
  description = "ThreatMAMBA: cyber threat attribution from CTI reports (TTPs, IOCs, CSKG, GAT+MAMBA)"
  visibility  = "public"
  topics      = ["cyber-threat-intelligence", "threat-attribution", "mitre-attack", "fastapi"]

  has_issues   = true
  has_projects = true
  has_wiki     = false

  # promotion PRs keep shared history: merge commits only, never delete develop/QA after a merge
  allow_merge_commit     = true
  allow_squash_merge     = false
  allow_rebase_merge     = false
  allow_auto_merge       = false
  delete_branch_on_merge = false

  lifecycle {
    prevent_destroy = true        # `terraform destroy` must never delete the project
    ignore_changes  = [auto_init] # create-time only; irrelevant for an adopted repo
  }
}

resource "github_repository_vulnerability_alerts" "this" {
  repository = github_repository.this.name
  enabled    = true # Dependabot alerts
}

# GITHUB_TOKEN is read-only by default; each workflow job asks for the extra rights it needs
resource "github_workflow_repository_permissions" "this" {
  repository                       = github_repository.this.name
  default_workflow_permissions     = "read"
  can_approve_pull_request_reviews = false
}

resource "github_branch_default" "this" {
  repository = github_repository.this.name
  branch     = "develop"
}

locals {
  # branch => status checks that must be green before a PR can merge into it
  protected_branches = {
    develop = ["ci-passed"]
    QA      = ["ci-passed", "promotion-guard"]
    main    = ["ci-passed", "promotion-guard"]
  }
}

resource "github_repository_ruleset" "branch" {
  for_each    = local.protected_branches
  name        = "protect-${lower(each.key)}"
  repository  = github_repository.this.name
  target      = "branch"
  enforcement = var.rules_enforcement

  conditions {
    ref_name {
      include = ["refs/heads/${each.key}"]
      exclude = []
    }
  }

  rules {
    deletion         = true # branch cannot be deleted
    non_fast_forward = true # no force-push

    pull_request {
      required_approving_review_count   = var.required_approvals
      dismiss_stale_reviews_on_push     = true
      require_code_owner_review         = false # a code owner cannot approve their own PR
      require_last_push_approval        = false
      required_review_thread_resolution = false
    }

    required_status_checks {
      strict_required_status_checks_policy = false # "up to date" would block every promotion
      dynamic "required_check" {
        for_each = each.value
        content {
          context = required_check.value
        }
      }
    }
  }

  depends_on = [github_branch_default.this]
}

# Deployments tab: each push to develop / QA / main shows up as a delivery to this environment
resource "github_repository_environment" "env" {
  for_each    = toset(["develop", "qa", "release"])
  repository  = github_repository.this.name
  environment = each.key
}

resource "github_repository_collaborator" "team" {
  for_each   = var.collaborators
  repository = github_repository.this.name
  username   = each.key
  permission = each.value
}
