rule RedTeam_Exfil {
    strings: $ = "ExfiltrationTool"
    condition: all of them
}