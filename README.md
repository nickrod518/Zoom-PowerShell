# Zoom-PowerShell
PowerShell module to help manage Zoom cloud environment

To get started, create an API key and secret within Zoom. Then just set the auth context and begin scripting:
```
# Set auth context
$key = 'my api key'
$secret = 'my api secret'
Import-Module Zoom
Set-ZoomApiAuth -Key $key -Secret $secret

# Try out some commands here
Get-ZoomUser -All
```

For help with any of the commands you can use the comment based help, for example ```Get-Help Get-ZoomUser```
