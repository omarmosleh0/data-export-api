TABLE_REGISTRY = {
    "projects": {
        "name": "intern_projects",
        "columns": ["project_id", "project_name", "status", "assigned_to", "due_date"],
        "primary_key": "project_id" 
}
}

##WHY ADDED?
##Adding a new table requires only config changes (no code deploys).
##Security team can audit all accessible tables in one file.
