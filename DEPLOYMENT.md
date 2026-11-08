# Deployment notes

The included Render blueprint is a basic deployment starting point. The free service's local filesystem is not durable; uploaded files and SQLite data may be lost on restart, redeploy, or instance replacement. Configure a managed persistent database and private object storage before using this with real documents. Set a strong SECRET_KEY in the hosting dashboard. Do not upload `.env` or secrets to GitHub.
