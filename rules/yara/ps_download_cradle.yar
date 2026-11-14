rule PowerShell_Download_Cradle
{
    meta:
        author = "Aditi Nagpure"
        description = "Detects PowerShell scripts that download remote code and run it straight from memory (download cradle)"
        date = "2026-11-14"
        reference = "https://attack.mitre.org/techniques/T1059/001/"
        mitre_attack = "T1059.001, T1105"

    strings:
        $dl1 = "DownloadString" ascii wide nocase
        $dl2 = "DownloadData" ascii wide nocase
        $dl3 = "Invoke-WebRequest" ascii wide nocase
        $dl4 = "Net.WebClient" ascii wide nocase
        $ex1 = /\bIEX\b/ ascii wide nocase
        $ex2 = "Invoke-Expression" ascii wide nocase

    condition:
        filesize < 1MB and any of ($dl*) and any of ($ex*)
}