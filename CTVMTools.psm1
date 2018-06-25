function Stop-CTVMProcess {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true,
      ValueFromPipeline = $true
    )]
    [System.Diagnostics.Process]
    $Process,

    [switch]
    $IgnoreStopFailure
  )
  process {
    try {
      $Process |
        Stop-Process -Force -ErrorAction Ignore

      $Process = $Process | Get-Process

      if ($Process.HasExited) {
        return
      }

      $Process.Kill()

      Start-Sleep -Milliseconds 250 # Wait for the 'kill' to propagate.

      $Process = $Process | Get-Process

      if ($Process.HasExited -or $IgnoreStopFailure) {
        return
      }
      else {
        throw "Failed to stop '$($Process.Name)' process."
      }
    } catch {
      $PSCmdlet.ThrowTerminatingError($_)
    }
  }
}

function Reset-CTVMHost {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [ValidateSet("Not Configured", "Enabled", "Disabled")]
    [string]
    $SetEnhancedSessionMode = "Disabled",

    [switch]
    $StopVMConnect,

    [switch]
    $StopHVManager,

    [switch]
    $IgnoreStopFailure
  )
  try {

    # Default. Resetting host state implies closing open vm connections and
    # hyper-vm manager. Must be *specifically* negated to disable.
    if (-not $PSBoundParameters.ContainsKey("StopVMConnect")) {
      $StopVMConnect = $true
    }
    if (-not $PSBoundParameters.ContainsKey("StopHVManager")) {
      $StopHVManager = $true
    }

    # Legacy behavior. Probably unnecessary in most contexts where it is used.
    $vmmsService = Get-Service |
                     Where-Object Name -eq vmms

    if ($vmmsService -eq $null -or $vmmsService.Status -ne "Running") {
      throw "The virtual machine management service (vmms) is absent or not running on this host."
    }

    if ($StopVMConnect) {
      Get-Process |
        Where-Object Name -eq vmconnect |
        Stop-CTVMProcess -IgnoreStopFailure:$IgnoreStopFailure
    }

    if ($StopHVManager) {
      Get-Process |
        Where-Object Name -eq mmc |
        Where-Object MainWindowTitle -eq "Hyper-V Manager" |
        Stop-CTVMProcess -IgnoreStopFailure:$IgnoreStopFailure
    }

    if ($SetEnhancedSessionMode -ne "Not Configured") {
      Set-VMHost -EnableEnhancedSessionMode:($SetEnhancedSessionMode -eq "Enabled")
    }

  } catch {
    $PSCmdlet.ThrowTerminatingError($_)
  }
}

function Start-CTVMProcess_Maximized {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true
    )]
    [string]
    $FilePath,

    [string]
    $Arguments
  )
  # Since according to my new spec this function should only run *ONCE*, it's
  # appropriate to declare the type in here.
  Add-Type @"
using System;
using System.Runtime.InteropServices;

public class WindowTricks {
  [DllImport("user32.dll")] 
  public static extern bool SetForegroundWindow (IntPtr hWnd);

  [DllImport("user32.dll")]
  public static extern IntPtr SetActiveWindow (IntPtr hWnd);

  [DllImport("user32.dll")]
  public static extern IntPtr SetFocus (IntPtr hWnd);

  [DllImport("user32.dll")]
  private static extern int SendMessage (int hWnd, int msg, int wParam, int lParam);
  public static int MaximizeWindow (int hWnd) {return SendMessage(hWnd, 0x0112, 0xF030, 0);}

  [StructLayout(LayoutKind.Sequential)]
  public struct RECT {
    public int Left;        // x position of upper-left corner
    public int Top;         // y position of upper-left corner
    public int Right;       // x position of lower-right corner
    public int Bottom;      // y position of lower-right corner
  }

  [DllImport("user32.dll")]
  static extern bool GetClientRect(int hWnd, out RECT lpRect);
  public static int GetClientWidth(int hWnd) {
    RECT rct;

    if(!GetClientRect(hWnd, out rct )) {
      return 0;
    }

    return rct.Right - rct.Left;
  }
}
"@

  $processInfo = @{
    ProcessObject      = $null
    MainWindowHandle   = 0
    WindowIsForeground = $false
    WindowIsActive     = $false
    WindowIsFocused    = $false
    VMConnectHasVideo  = $false
    WindowIsMaximized  = $false
  }

  $startTime = [datetime]::Now

  while ($true) {
    if ($null -eq $processInfo.ProcessObject) {
      $params = @{
        FilePath     = $FilePath
        ArgumentList = $Arguments
        PassThru     = $true
      }

      # Most programs will honor the Start-Process "WindowStyle" parameter, in
      # which case none of the proceeding dance is needed.
      if ($FilePath -notlike "*\vmconnect.exe") {
        $params.WindowStyle = "Maximized"

        $processInfo.MainWindowHandle   = -1
        $processInfo.WindowIsForeground = $true
        $processInfo.WindowIsActive     = $true
        $processInfo.WindowIsFocused    = $true
        $processInfo.VMConnectHasVideo  = $true
        $processInfo.WindowIsMaximized  = $true
      }

      $processInfo.ProcessObject = Start-Process @params
      continue
    }

    if (((Get-Date) - $startTime).TotalMinutes -ge 2) {
      throw "Window 'Maximized' status was not confirmed within timeout threshold of 2 minutes."
    }

    Start-Sleep -Seconds 3

    # For vmconnect.exe, on the other hand, making it appear full screen
    # requires a very specific dance:

    # 1) Window Handle does not populate immediately in the process object.
    if ($processInfo.MainWindowHandle -eq 0) {
      $processInfo.MainWindowHandle = (Get-Process -Id $processInfo.ProcessObject.Id).MainWindowHandle
      continue
    }

    # 2) Foreground
    if (-not $processInfo.WindowIsForeground) {
      [WindowTricks]::SetForegroundWindow($processInfo.MainWindowHandle) | Out-Null
      $processInfo.WindowIsForeground = $true
      continue
    }

    # 3) Active
    if (-not $processInfo.WindowIsActive) {
      [WindowTricks]::SetActiveWindow($processInfo.MainWindowHandle) | Out-Null
      $processInfo.WindowIsActive = $true
      continue
    }

    # 4) Focused
    if (-not $processInfo.WindowIsFocused) {
      [WindowTricks]::SetFocus($processInfo.MainWindowHandle) | Out-Null
      $processInfo.WindowIsFocused = $true
      continue
    }

    # 5) The vmconnect.exe application intercepts calls to the "Maximize" api
    #    method and full-screens the connection. It will not do so, however,
    #    until it has received a video feed from the virtual machine. Window
    #    size at startup is 640x480; the "recommended" resolution for a vm is
    #    1024x768, and the window will resize to fit when it receives video.
    #    Thus, if window width -gt 640, it is ready to be maximized.
    if (-not $processInfo.VMConnectHasVideo) {
      $processInfo.VMConnectHasVideo = [WindowTricks]::GetClientWidth($processInfo.MainWindowHandle) -gt 640
      continue
    }

    # 6) As above, API call is *intercepted* by vmconnect.exe application and
    #    used as signal to full-screen. This is effective at least as of W10
    #    v1709. To produce the same effect in some earlier builds of W10, I
    #    had to use SendKeys to send the Ctrl+Alt+Break key sequence to the
    #    window.
    if (-not $processInfo.WindowIsMaximized) {
      [WindowTricks]::MaximizeWindow($processInfo.MainWindowHandle) | Out-Null
      $processInfo.WindowIsMaximized = $true
      continue
    }

    break
  }
}

function Start-CTVMProcess_Minimized {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true
    )]
    [string]
    $FilePath,

    [string]
    $Arguments
  )

  # @TODO: This was taken pretty much verbatim from somewhere online, back when
  #        I was too green to understand how it worked. Now that I have a
  #        better idea of what it's doing, I should probably clean it up.

  Add-Type -TypeDefinition @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
 
[StructLayout(LayoutKind.Sequential)]
public struct PROCESS_INFORMATION {
  public IntPtr hProcess;
  public IntPtr hThread;
  public uint dwProcessId;
  public uint dwThreadId;
}
 
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct STARTUPINFO {
  public uint cb;
  public string lpReserved;
  public string lpDesktop;
  public string lpTitle;
  public uint dwX;
  public uint dwY;
  public uint dwXSize;
  public uint dwYSize;
  public uint dwXCountChars;
  public uint dwYCountChars;
  public uint dwFillAttribute;
  public STARTF dwFlags;
  public ShowWindow wShowWindow;
  public short cbReserved2;
  public IntPtr lpReserved2;
  public IntPtr hStdInput;
  public IntPtr hStdOutput;
  public IntPtr hStdError;
}
 
[StructLayout(LayoutKind.Sequential)]
public struct SECURITY_ATTRIBUTES {
  public int length;
  public IntPtr lpSecurityDescriptor;
  public bool bInheritHandle;
}
 
[Flags]
public enum CreationFlags : int {
  NONE = 0,
  DEBUG_PROCESS = 0x00000001,
  DEBUG_ONLY_THIS_PROCESS = 0x00000002,
  CREATE_SUSPENDED = 0x00000004,
  DETACHED_PROCESS = 0x00000008,
  CREATE_NEW_CONSOLE = 0x00000010,
  CREATE_NEW_PROCESS_GROUP = 0x00000200,
  CREATE_UNICODE_ENVIRONMENT = 0x00000400,
  CREATE_SEPARATE_WOW_VDM = 0x00000800,
  CREATE_SHARED_WOW_VDM = 0x00001000,
  CREATE_PROTECTED_PROCESS = 0x00040000,
  EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
  CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
  CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
  CREATE_DEFAULT_ERROR_MODE = 0x04000000,
  CREATE_NO_WINDOW = 0x08000000,
}
 
[Flags]
public enum STARTF : uint {
  STARTF_USESHOWWINDOW = 0x00000001,
  STARTF_USESIZE = 0x00000002,
  STARTF_USEPOSITION = 0x00000004,
  STARTF_USECOUNTCHARS = 0x00000008,
  STARTF_USEFILLATTRIBUTE = 0x00000010,
  STARTF_RUNFULLSCREEN = 0x00000020,  // ignored for non-x86 platforms
  STARTF_FORCEONFEEDBACK = 0x00000040,
  STARTF_FORCEOFFFEEDBACK = 0x00000080,
  STARTF_USESTDHANDLES = 0x00000100,
}
 
public enum ShowWindow : short {
  SW_HIDE = 0,
  SW_SHOWNORMAL = 1,
  SW_NORMAL = 1,
  SW_SHOWMINIMIZED = 2,
  SW_SHOWMAXIMIZED = 3,
  SW_MAXIMIZE = 3,
  SW_SHOWNOACTIVATE = 4,
  SW_SHOW = 5,
  SW_MINIMIZE = 6,
  SW_SHOWMINNOACTIVE = 7,
  SW_SHOWNA = 8,
  SW_RESTORE = 9,
  SW_SHOWDEFAULT = 10,
  SW_FORCEMINIMIZE = 11,
  SW_MAX = 11
}
 
public static class Kernel32 {
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool CreateProcess(
        string lpApplicationName, 
        string lpCommandLine, 
        ref SECURITY_ATTRIBUTES lpProcessAttributes, 
        ref SECURITY_ATTRIBUTES lpThreadAttributes,
        bool bInheritHandles, 
        CreationFlags dwCreationFlags, 
        IntPtr lpEnvironment,
        string lpCurrentDirectory, 
        ref STARTUPINFO lpStartupInfo, 
        out PROCESS_INFORMATION lpProcessInformation);
}
"@
 
  $si = New-Object STARTUPINFO
  $pi = New-Object PROCESS_INFORMATION
 
  $si.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($si)
  $si.wShowWindow = [ShowWindow]::SW_SHOWMINNOACTIVE
  $si.dwFlags = [STARTF]::STARTF_USESHOWWINDOW
 
  $pSec = New-Object SECURITY_ATTRIBUTES
  $tSec = New-Object SECURITY_ATTRIBUTES
  $pSec.Length = [System.Runtime.InteropServices.Marshal]::SizeOf($pSec)
  $tSec.Length = [System.Runtime.InteropServices.Marshal]::SizeOf($tSec)

  [Kernel32]::CreateProcess(
    $FilePath,                           # ApplicationName    -- Full path to file.
    "`"$FilePath`" $Arguments",          # CommandLine        -- Yup; this is really how you specify an argument in this context.
    [ref]$pSec,                          # ProcessAttributes
    [ref]$tSec,                          # ThreadAttributes
    $false,                              # InheritHandles
    [CreationFlags]::CREATE_NEW_CONSOLE, # CreationFlags
    [IntPtr]::Zero,                      # Environment
    "C:\",                               # CurrentDirectory
    [ref]$si,                            # StartupInfo
    [ref]$pi                             # ProcessInformation
  ) | Out-Null
 
  #[System.Runtime.InteropServices.Marshal]::GetLastWin32Error()

  # Provides basic throttling for this function, as it may be .
  Start-Sleep -Seconds 3
}

function Start-CTVMConnect {
  [CmdletBinding(
    PositionalBinding = $true
  )]
  param(
    [Microsoft.HyperV.PowerShell.VirtualMachine[]]
    $VM = [Microsoft.HyperV.PowerShell.VirtualMachine[]]@(),

    [switch]
    $UseImmersiveVMConnect,

    [switch]
    $StartHVManager
  )

  $immersiveConnectPath = "C:\Program Files\CTVMConnect\CTVMConnect.exe"

  if (
    $UseImmersiveVMConnect -and (
      $VM.Count -ne 1 -or
      $StartHVManager -or
      (-not (Test-Path -LiteralPath $immersiveConnectPath -PathType Leaf))
    )
  ) {
    throw "An immersive vm connection is only available when one vm will be used, when hyper-v manager will not be started, and when the path to the custom executable exists on the host."
  }

  if ($StartHVManager) {
    $modeMaxMap = @{
      $true  = "Maximized"
      $false = "Minimized"
    }

    & "Start-CTVMProcess_$($modeMaxMap.($VM.Count -eq 0))" -FilePath C:\Windows\System32\mmc.exe -Arguments C:\Windows\System32\virtmgmt.msc
  }

  $MainVM = $VM |
              Select-Object -First 1

  $OtherVMs = @(
    $VM |
      Select-Object -Skip 1
  )

  foreach ($OtherVM in $OtherVMs) {
    Start-CTVMProcess_Minimized -FilePath C:\Windows\System32\vmconnect.exe -Arguments "localhost -G $($OtherVM.Id)"
  }

  if ($null -ne $MainVM -and $UseImmersiveVMConnect) {
    Start-CTVMProcess_Maximized -FilePath $immersiveConnectPath -Arguments $MainVM.Id
  }
  elseif ($null -ne $MainVM) {
    Start-CTVMProcess_Maximized -FilePath C:\Windows\System32\vmconnect.exe -Arguments "localhost -G $($MainVM.Id)"
  }
}

Export-ModuleMember -Function Reset-CTVMHost,
                              Start-CTVMConnect