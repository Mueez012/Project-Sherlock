variable "owner" {
  description = "GitHub user or organization that owns the repo"
  type        = string
}

variable "repo_name" {
  description = "Repository name"
  type        = string
  default     = "threatmamba"
}

variable "collaborators" {
  description = "Teammates and their access, e.g. { alice = \"push\", bob = \"push\" }"
  type        = map(string)
  default     = {}
}

variable "required_approvals" {
  description = "Approvals needed on every PR (1 for a team; 0 only while testing alone)"
  type        = number
  default     = 1
}

variable "rules_enforcement" {
  description = "active, or disabled to switch every rule off temporarily"
  type        = string
  default     = "active"
  validation {
    condition     = contains(["active", "disabled"], var.rules_enforcement)
    error_message = "rules_enforcement must be active or disabled."
  }
}
