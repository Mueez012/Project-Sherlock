output "repo_url" {
  value = github_repository.this.html_url
}

output "clone_url" {
  value = github_repository.this.ssh_clone_url
}
