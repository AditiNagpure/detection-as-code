rule HTML_Smuggling_Blob_Download
{
    meta:
        author = "Aditi Nagpure"
        description = "Detects HTML attachments that rebuild a file from Base64 inside the browser and force a download (HTML smuggling), used to slip payloads past email gateways"
        date = "2026-11-14"
        reference = "https://attack.mitre.org/techniques/T1027/006/"
        mitre_attack = "T1027.006, T1566.001"

    strings:
        $html = "<html" ascii wide nocase
        $b64 = "atob(" ascii wide nocase
        $blob = "new Blob(" ascii wide nocase
        $save1 = "URL.createObjectURL" ascii wide nocase
        $save2 = "msSaveOrOpenBlob" ascii wide nocase
        $dl = ".download" ascii wide nocase

    condition:
        filesize < 5MB and $html and $b64 and $blob and any of ($save*) and $dl
}