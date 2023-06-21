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

# Disclaimer
THIS SCRIPT IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE, AND/OR NONINFRINGEMENT. 

This script is not supported under any Tripwire standard support program or service. The script is provided AS IS without warranty of any kind. I further disclaim all implied warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose. The entire risk arising out of the use or performance of the sample and documentation remains with you. In no event shall I (the script's author), or anyone else involved in the creation, production, or delivery of the script be liable for any damages whatsoever (including, without limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss) arising out of the use of or inability to use the sample or documentation, even if I have  been advised of the possibility of such damages.

WITHOUT LIMITING THE GENERALITY OF THE FOREGOING, I HAVE NO OBLIGATION TO INDEMNIFY OR DEFEND RECIPIENT AGAINST CLAIMS RELATED TO INFRINGEMENT OF INTELLECTUAL PROPERTY RIGHTS.
