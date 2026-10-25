# The self-hosted CI runner: start, stop, status, and install to start at logon.
#
# The runner is what checks every pull request on this repository, because the
# repository is private and its GitHub-hosted minutes are billed. It has gone
# offline three times so far — it does not survive a reboot on its own — and
# each time the symptom was a pull request whose checks sat in "queued" looking
# like nothing was wrong.
#
#   .\scripts\runner.ps1 status     is it up?
#   .\scripts\runner.ps1 start      start it now
#   .\scripts\runner.ps1 stop       stop it (when you are not working)
#   .\scripts\runner.ps1 install    start it automatically at logon
#   .\scripts\runner.ps1 uninstall  stop starting it automatically
#
# `install` creates a Scheduled Task rather than a Windows service, on purpose:
# a service needs an elevated prompt, and a task at logon does not. It also runs
# as you, so the runner sees the same Node, npm cache and Playwright browsers a
# manual run does — a service under SYSTEM would not, and the difference would
# show up as a build that fails only in CI.

param(
  [Parameter(Position = 0)]
  [ValidateSet('status', 'start', 'stop', 'install', 'uninstall')]
  [string]$Action = 'status'
)

$ErrorActionPreference = 'Stop'

$RunnerDir = 'C:\actions-runner'
$RunnerCmd = Join-Path $RunnerDir 'run.cmd'
$TaskName = 'LUME GitHub Actions runner'

function Get-Runner {
  Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -eq 'Runner.Listener' }
}

function Show-Status {
  $p = Get-Runner
  if ($p) {
    Write-Host "Runner is UP (pid $($p.Id -join ', '))."
  } else {
    Write-Host "Runner is DOWN. Pull request checks will queue until it is started."
  }

  $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
  if ($task) {
    Write-Host "Starts at logon: yes."
  } else {
    Write-Host "Starts at logon: no  (.\scripts\runner.ps1 install)"
  }
}

switch ($Action) {
  'status' { Show-Status }

  'start' {
    if (Get-Runner) { Write-Host 'Already running.'; break }
    if (-not (Test-Path $RunnerCmd)) { throw "No runner at $RunnerCmd." }

    # Prefer the Scheduled Task. `Start-Process` makes the runner a child of
    # whatever shell called it, so it dies when that shell exits — which looked
    # like it worked (status said UP) and then silently left checks queueing a
    # minute later. The task scheduler starts it detached, the way the logon
    # trigger does.
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($task) {
      Start-ScheduledTask -TaskName $TaskName
    } else {
      Write-Host 'Not installed as a logon task — starting a child process instead.'
      Write-Host 'It will stop when this shell exits. Run `install` to make it stick.'
      Start-Process -FilePath $RunnerCmd -WorkingDirectory $RunnerDir -WindowStyle Hidden
    }

    Start-Sleep -Seconds 10
    Show-Status
  }

  'stop' {
    $p = Get-Runner
    if (-not $p) { Write-Host 'Not running.'; break }
    # A job in flight is killed with it. That is the intent of `stop`, and the
    # run reports as failed on GitHub rather than hanging — re-run it after
    # starting the runner again.
    $p | Stop-Process -Force
    Write-Host 'Stopped.'
  }

  'install' {
    if (-not (Test-Path $RunnerCmd)) { throw "No runner at $RunnerCmd." }
    # Not $action: PowerShell variables are case-insensitive, so it would
    # collide with this script's own -Action parameter and fail its ValidateSet.
    $taskAction = New-ScheduledTaskAction -Execute $RunnerCmd -WorkingDirectory $RunnerDir
    $taskTrigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
    # No execution time limit: this is a long-lived listener, not a batch job,
    # and the default would kill it after three days.
    $taskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries `
      -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -Hidden
    Register-ScheduledTask -TaskName $TaskName -Action $taskAction -Trigger $taskTrigger `
      -Settings $taskSettings -Description 'Runs LUME CI on this machine so the private repository does not need billed minutes.' -Force | Out-Null
    Write-Host "Installed. It will start at every logon."
    Write-Host "Stop it any time with: .\scripts\runner.ps1 stop"
  }

  'uninstall' {
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if (-not $task) { Write-Host 'Not installed.'; break }
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Host 'Removed from logon. The runner keeps running until you stop it.'
  }
}
