package zerotrust.files

import rego.v1

default allow := false

# Compliant administrators can perform actions allowed by the app.
allow if {
    input.role == "admin"
    input.device == "compliant"
}

# Employees and analysts may upload when compliant.
allow if {
    input.action == "upload"
    input.role in {"employee", "analyst"}
    input.device == "compliant"
}

# A user may download their own file when compliant.
allow if {
    input.action == "download"
    input.owner == input.user
    input.device == "compliant"
}

# Analysts may download internal-classification files when compliant.
allow if {
    input.action == "download"
    input.role == "analyst"
    input.classification == "internal"
    input.device == "compliant"
}