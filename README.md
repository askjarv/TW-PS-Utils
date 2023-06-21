# TW-PS-Utils
A series of PowerShell commandlets for managing Tripwire Enterprise (tested with version 9.0, but should work with must versions that support the REST API).

# Usage
- Import the PowerShell module
- Authenticate/connect to your Tripwire Enterprise server:
Get-TEAPILogin -teserver "YourTEserver" -tepass "YourTEpassword" -teuser "yourTEusername"
- You're ready to go - for example, to get a list of nodes:
Get-TENodes

# Todo
- I'm adding more functions from the various other endpoints
- More robust error handling/validation of inputs
- Automated testing 
