
function AddToEnvironment($env_name, $value, $seperate = ';', $level = "User")
{
    $env_value = [environment]::GetEnvironmentVariable($env_name, $level)
    if ($env_value -eq '') {
        $env_value = $value
    } else {
        foreach ($i in $env_value -split $seperate)
        {
            if ($i -eq $value) { return }
        }
        $env_value = $env_value + $seperate + $value
    }
    echo "Set $env_name to $env_value"
    [environment]::SetEnvironmentVariable($env_name, $env_value, $level)
}

AddToEnvironment 'IDAUSR' $PSScriptRoot
