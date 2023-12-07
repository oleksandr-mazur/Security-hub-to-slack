variable "IncomingWebHookURL" {
  type        = string
  description = "Incoming Webhook URL for slack app. To create follow this [Doc](https://api.slack.com/messaging/webhooks#getting_started)"
}

variable "SlackChannel" {
  type        = string
  description = "Slack Chennel Name"
  default     = "security_alerts"
}

variable "projectName" {
  type        = string
  description = "Project Name"
  default     = "Unknown"
}

variable "severityLevels" {
  type        = string
  description = "Severity Levels"
  default     = "LOW,MEDIUM,HIGH,CRITICAL"
}

