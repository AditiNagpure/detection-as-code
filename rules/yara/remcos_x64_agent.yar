rule Remcos_x64_Agent
{
    meta:
        author = "Aditi Nagpure"
        description = "Detects the native x64 Remcos RAT agent (unpacked on disk or dumped from memory) by its built-in log strings and its WAV audio-capture code"
        date = "2026-11-18"
        reference = "https://attack.mitre.org/software/S0332/"
        mitre_attack = "T1056.001, T1123"
        sample_sha256 = "24a6ed8ce6aa9fb2c29a706882efd3f3e1dec98517fc0e50b36a09543b6c69e0"
        note = "Packed droppers (.NET wrappers, MPRESS) hide these strings on disk; scan the unpacked payload or a memory dump"

    strings:
        // Log messages the agent writes about its own state. Written by the
        // Remcos developer, not the attacker, so they don't change between campaigns.
        $agent  = "Remcos Agent initialized (" ascii wide
        $wd1    = "Remcos restarted by watchdog!" ascii wide
        $wd2    = "Watchdog module activated" ascii wide
        $wd3    = "Watchdog launch failed!" ascii wide
        $kl1    = "Offline Keylogger Started" ascii wide
        $kl2    = "Online Keylogger Started" ascii wide
        $kl3    = "Keylogger initialization failure: error" ascii wide
        $vendor = "BreakingSecurity.net" ascii wide

        // Start of the WAV header writer (VA 0x1400020c9 in the reference sample):
        // file attribute 0x80, PCM format 1, fmt chunk size 0x10, then bits / 8.
        // Stack offsets and the global's address are wildcarded (??) because
        // they move between builds; the constants are the audio logic itself.
        $wav = { C7 44 24 ?? 80 00 00 00 45 8D 7E 02 C7 45 ?? 01 00 00 00
                 C7 45 ?? 10 00 00 00 41 8B C0 44 89 7C 24 ?? 0F AF 05 ?? ?? ?? ??
                 C1 E8 03 89 45 ?? }

    condition:
        uint16(0) == 0x5A4D and filesize < 5MB and
        (
            3 of ($agent, $wd*, $kl*, $vendor) or
            ($wav and 1 of ($agent, $wd*, $kl*, $vendor))
        )
}
