$p = Get-CimInstance Win32_Process -Filter "ProcessId=32128"
"Started: " + $p.CreationDate
"Cmd: " + $p.CommandLine
$pp = Get-CimInstance Win32_Process -Filter ("ProcessId=" + $p.ParentProcessId)
"ParentCmd: " + $pp.CommandLine
