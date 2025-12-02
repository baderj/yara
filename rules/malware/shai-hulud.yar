rule win_shai_hulud_2 {

    meta:
        author      = "Johannes Bader @viql"
        date        = "2025-11-26"
        description = "detects Shai-Hulud-2.0, bun_environment.js"
        version     = "v1.0"
        tlp         = "TLP:WHITE"

    strings:
        $url_01 = "https://api.github.com/repos/trufflesecurity/trufflehog/releases/latest"
        $url_02 = "https://aka.ms/azsdk/js/identity/workloadidentitycredential/troubleshoot"
        $url_03 = "https://secretsmanager."
        $url_04 = "https://secretsmanager-fips"
        $url_05 = "https://github.com/actions/runner/releases/download/"
        $url_06 = "https://sts.{Region}.{PartitionResult#dualStackDnsSuffix}"

        $func_01 = "initialize"
        $func_02 = "scanFilesystem"
        $func_03 = "scanGitRepo"
        $func_04 = "scanLocalGit"
        $func_05 = "getVerifiedFindings"
        $func_06 = "getFindingsByDetector"
        $func_07 = "getFindingsByFile"
        $func_08 = "getSummary"
        $func_09 = "executeWithTimeout"
        $func_10 = "parseOutput"
        $func_11 = "findCachedBinary"
        $func_12 = "fetchLatestRelease"
        $func_13 = "normalizeArch"
        $func_14 = "pickAsset"
        $func_15 = "extractAndInstall"
        $func_16 = "runCommand"

    condition:
        12 of ($func_*) and 4 of ($url_*) 
}