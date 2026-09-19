rule Example_Rule {
    meta:
        description = "Sample YARA rule placeholder"
    strings:
        $s1 = "suspicious_string"
    condition:
        $s1
}
