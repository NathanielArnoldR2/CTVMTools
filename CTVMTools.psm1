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

function Test-CTVMHostStandardVMSwitch {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [switch]
    $Repair
  )

function Test-CTVMSwitch {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true
    )]
    $SwitchName,

    [Parameter(
      Mandatory = $true
    )]
    $SwitchType
  )

  try {
    $switches = @(
      Get-VMSwitch |
        Where-Object Name -eq $SwitchName
    )

    if ($switches.Count -ne 1 -or $switches[0].Name -cne $SwitchName -or $switches[0].SwitchType -ne $SwitchType) {
      return $false
    }

    if ($SwitchType -eq "External" -and (-not $switches[0].AllowManagementOS)) {
      return $false
    }

    return $true

  } catch {
    $PSCmdlet.ThrowTerminatingError($_)
  }
}
function Repair-CTVMSwitch {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true
    )]
    $SwitchName,

    [Parameter(
      Mandatory = $true
    )]
    $SwitchType
  )

  try {
    Get-VMSwitch |
      Where-Object Name -eq $SwitchName |
      Remove-VMSwitch -Force

    $switches = @(
      Get-VMSwitch |
        Where-Object Name -eq $SwitchName
    )

    if ($switches.Count -gt 0) {
      throw "Validation of switch '$SwitchName' properties failed, and automated repair failed to remove existing switch(es) with that name."
    }

    $switchParams = @{
      Name = $SwitchName
    }

    if ($SwitchType -eq "External") {

      # Adapter must stem from hardware FROM THE OS POV -- e.g. a guest
      # would return $true for a virtual adapter defined from the host,
      # and attached to its virtual hardware load, but $false for a
      # virtual adapter defined by itself.
      $adapter = @(
        Get-NetAdapter |
          Where-Object HardwareInterface -eq $true
      )

      # If there is more than one hardware option for attachment (e.g. Wi-Fi),
      # we want the one that attaches using a wired ethernet cable. FYI, this
      # means the function supports virtual machines with no more than *one*
      # hardware virtual adapter, since any virtual adapter will present a
      # PhysicalMediaType of "Unspecified".
      if ($adapter.Count -gt 1) {
        $adapter = @(
          $adapter |
            Where-Object PhysicalMediaType -eq 802.3
        )
      }

      # If there is more than one Ethernet NIC attached to a physical system,
      # we need to attach a cable to exactly *one* so the function knows
      # which one to piggyback.
      if ($adapter.Count -gt 1) {
        $adapter = @(
          $adapter |
            Where-Object ConnectorPresent -eq $true
        )
      }

      if ($adapter.Count -ne 1) {
        throw "Validation of '$SwitchType' switch '$SwitchName' failed, and automated repair failed to find an unambiguous host adapter for connection. Best to create this switch manually."
      }

      $switchParams.NetAdapterInterfaceDescription = $adapter[0].InterfaceDescription
    }
    else {
      $switchParams.SwitchType = $SwitchType
    }

    New-VMSwitch @switchParams | Out-Null

    if (-not (Test-CTVMSwitch -SwitchName $SwitchName -SwitchType $SwitchType)) {
      throw "Validation of switch '$SwitchName' properties failed, and automated repair failed for an unknown reason."
    }
  } catch {
    $PSCmdlet.ThrowTerminatingError($_)
  }
}

  try {
    "Private",
    "Internal",
    "External" |
      ForEach-Object {
        $switchType = $_
        $switchName = "CT$($switchType)"

        if (Test-CTVMSwitch -SwitchName $switchName -SwitchType $switchType) {
          return
        }

        if (-not $Repair) {
          throw "Virtual switch '$switchName' was absent or misconfigured, and repair was not indicated."
        }

        Repair-CTVMSwitch -SwitchName $switchName -SwitchType $switchType
      }
  } catch {
    $PSCmdlet.ThrowTerminatingError($_)
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

function Start-CTVMConnect {
  [CmdletBinding(
    PositionalBinding = $false,
    DefaultParameterSetName = "InactiveVMConnect"
  )]
  param(
    [Parameter(
      ParameterSetName = "MaximizedVMConnect",
      Mandatory = $true
    )]
    [Microsoft.HyperV.PowerShell.VirtualMachine]
    $MaximizedVM,

    [Parameter(
      ParameterSetName = "CenteredVMConnect",
      Mandatory = $true
    )]
    [Microsoft.HyperV.PowerShell.VirtualMachine]
    $CenteredVM,

    [Microsoft.HyperV.PowerShell.VirtualMachine[]]
    $InactiveVMs = [Microsoft.HyperV.PowerShell.VirtualMachine[]]@(),

    [Parameter(
      ParameterSetName = "MaximizedVMConnect"
    )]
    [Parameter(
      ParameterSetName = "CenteredVMConnect"
    )]
    [switch]
    $SkipVMVideoCheck,

    [switch]
    $StartHyperVManager
  )

Add-Type -TypeDefinition @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace CTVMTools {
  namespace ProcessTricks {

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
      SW_SHOWMINIMIZED = 2,
      SW_SHOWMAXIMIZED = 3,
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

    public class Kernel32 {
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
        out PROCESS_INFORMATION lpProcessInformation
      );
    }
  }

  public class WindowTricks {
    [DllImport("user32.dll")] 
    public static extern bool SetForegroundWindow (IntPtr hWnd);
  
    [DllImport("user32.dll")]
    public static extern IntPtr SetActiveWindow (IntPtr hWnd);
  
    [DllImport("user32.dll")]
    public static extern IntPtr SetFocus (IntPtr hWnd);
  
    [StructLayout(LayoutKind.Sequential)]
    private struct RECT {
      public int left;        // x position of upper-left corner
      public int top;         // y position of upper-left corner
      public int right;       // x position of lower-right corner
      public int bottom;      // y position of lower-right corner
    }
  
    [DllImport("user32.dll")]
    private static extern bool GetClientRect(int hWnd, out RECT lpRect);

    public static int GetWindowClientWidth(int hWnd) {
      RECT rct;
  
      if(!GetClientRect(hWnd, out rct )) {
        return 0;
      }
  
      return rct.right - rct.left;
    }

    [DllImport("user32.dll")]
    private static extern int SendMessage (int hWnd, int msg, int wParam, int lParam);
    public static int MaximizeWindow (int hWnd) {return SendMessage(hWnd, 0x0112, 0xF030, 0);}

    [DllImport("user32.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall, ExactSpelling = true, SetLastError = true)]
    private static extern bool GetWindowRect(IntPtr hWnd, out RECT rect);

    [DllImport("user32.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall, ExactSpelling = true, SetLastError = true)]
    private static extern int GetSystemMetrics(int smIndex);

    [DllImport("user32.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall, ExactSpelling = true, SetLastError = true)]
    private static extern void MoveWindow(IntPtr hwnd, int X, int Y, int nWidth, int nHeight, bool bRepaint);

    public static void CenterWindow (IntPtr hWnd) {
      RECT rct;

      if(!GetWindowRect(hWnd, out rct )) {
        return;
      }

      int screenWidth = GetSystemMetrics(0);
      int screenHeight = GetSystemMetrics(1);

      int windowWidth = rct.right - rct.left;
      int windowHeight = rct.bottom - rct.top;

      MoveWindow(hWnd, (screenWidth / 2) - (windowWidth / 2), (screenHeight / 2) - (windowHeight / 2), windowWidth, windowHeight, true);
    }
  }
}
"@

function Start-CTVMConnect_EachVM {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true,
      ValueFromPipeline = $true
    )]
    [Microsoft.HyperV.PowerShell.VirtualMachine]
    $VM,

    [Parameter(
      Mandatory = $true
    )]
    [ValidateSet("Maximized","Centered","MinNoActive")]
    $WindowState,

    [switch]
    $SkipVMVideoCheck
  )
  process {
    try {
      $startupInfo = New-Object -TypeName CTVMTools.ProcessTricks.STARTUPINFO

      $startupInfo.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($startupInfo)
      $startupInfo.wShowWindow = if ($WindowState -in "Maximized","Centered") {
        [CTVMTools.ProcessTricks.ShowWindow]::SW_SHOWNORMAL
      } elseif ($WindowState -eq "MinNoActive") {
        [CTVMTools.ProcessTricks.ShowWindow]::SW_SHOWMINNOACTIVE
      }
      $startupInfo.dwFlags = [CTVMTools.ProcessTricks.STARTF]::STARTF_USESHOWWINDOW

      $processInfo = New-Object -TypeName CTVMTools.ProcessTricks.PROCESS_INFORMATION

      $processAttributes = New-Object -TypeName CTVMTools.ProcessTricks.SECURITY_ATTRIBUTES
      $processAttributes.Length = [System.Runtime.InteropServices.Marshal]::SizeOf($processAttributes)

      $threadAttributes = New-Object -TypeName CTVMTools.ProcessTricks.SECURITY_ATTRIBUTES
      $threadAttributes.Length = [System.Runtime.InteropServices.Marshal]::SizeOf($threadAttributes)

      $vmConnectPath = "C:\Windows\System32\vmconnect.exe"

      [CTVMTools.ProcessTricks.Kernel32]::CreateProcess(
        $vmConnectPath,                                              # ApplicationName (Full Path to executable.)
        "`"$vmConnectPath`" localhost -G $($VM.Id)",                 # CommandLine (Yup; this is really how you do it.)
        [ref]$processAttributes,                                     # ProcessAttributes
        [ref]$threadAttributes,                                      # ThreadAttributes
        $false,                                                      # InheritHandles
        [CTVMTools.ProcessTricks.CreationFlags]::CREATE_NEW_CONSOLE, # CreationFlags
        [System.IntPtr]::Zero,                                       # Environment
        "C:\",                                                       # CurrentDirectory
        [ref]$startupInfo,                                           # StartupInfo
        [ref]$processInfo                                            # ProcessInformation
      ) | Out-Null

      $windowInfo = [ordered]@{
        ProcessId    = $processInfo.dwProcessId
        Handle       = 0
        IsForeground = $false
        IsActive     = $false
        IsFocused    = $false
        HasVMVideo   = $false
        IsPositioned = $false
      }

      while ($true) {
        Start-Sleep -Seconds 3

        if ($windowInfo.Handle -eq 0) {
          $windowInfo.Handle = (Get-Process -Id $windowInfo.ProcessId).MainWindowHandle
          continue
        }

        if ($WindowState -eq "MinNoActive") {
          break # Process started; has a window. Nothing else to check.
        }

        ## 2) Foreground
        #if (-not $processInfo.WindowIsForeground) {
        #  [WindowTricks]::SetForegroundWindow($processInfo.MainWindowHandle) | Out-Null
        #  $processInfo.WindowIsForeground = $true
        #  continue
        #}
        #
        ## 3) Active
        #if (-not $processInfo.WindowIsActive) {
        #  [WindowTricks]::SetActiveWindow($processInfo.MainWindowHandle) | Out-Null
        #  $processInfo.WindowIsActive = $true
        #  continue
        #}
        #
        ## 4) Focused
        #if (-not $processInfo.WindowIsFocused) {
        #  [WindowTricks]::SetFocus($processInfo.MainWindowHandle) | Out-Null
        #  $processInfo.WindowIsFocused = $true
        #  continue
        #}

        if ($windowInfo.HasVMVideo -eq $false -and (Get-VM -Id $VM.Id).State -ne "Off" -and $SkipVMVideoCheck -eq $false) {
          $windowInfo.HasVMVideo = [CTVMTools.WindowTricks]::GetWindowClientWidth($windowInfo.Handle) -gt 640
          continue
        }

        if ($windowInfo.IsPositioned -eq $false) {
          if ($WindowState -eq "Maximized") {
            [CTVMTools.WindowTricks]::MaximizeWindow($windowInfo.Handle) | Out-Null
          } elseif ($WindowState -eq "Centered") {
            [CTVMTools.WindowTricks]::CenterWindow($windowInfo.Handle) | Out-Null
          }

          $windowInfo.IsPositioned = $true
        }

        break
      }

    } catch {
      $PSCmdlet.ThrowTerminatingError($_)
    }
  }
}

  try {
    if ($StartHyperVManager) {

      # mmc.exe will ignore the Start-Process "-WindowStyle" parameter, and due
      # to some elevation-related magic will not receive window messages from
      # unelevated processes. Hence, there is no way to ensure it is maximized
      # or well-positioned at class start. Best to leave it unimplemented
      # pending a solution that (let's face it) will likely never be found.
      throw "Not implemented!"

      #$hvProcess = Start-Process -FilePath C:\Windows\System32\mmc.exe -ArgumentList C:\Windows\System32\virtmgmt.msc -PassThru

      #do {
      #  Start-Sleep -Seconds 3

      #  $hvHWnd = (Get-Process -Id $hvProcess.Id).MainWindowHandle
      #} until ($hvHWnd -ne 0)

      #[CTVMTools.WindowTricks]::MaximizeWindow($hvHWnd) | Out-Null
    }

    $psHWnd = (Get-Process -Id $PID).MainWindowHandle

    $InactiveVMs |
      Start-CTVMConnect_EachVM -WindowState MinNoActive

    if ($PSCmdlet.ParameterSetName -eq "MaximizedVMConnect") {
      $MaximizedVM |
        Start-CTVMConnect_EachVM -WindowState Maximized -SkipVMVideoCheck:$SkipVMVideoCheck
    } elseif ($PSCmdlet.ParameterSetName -eq "CenteredVMConnect") {
      $CenteredVM |
        Start-CTVMConnect_EachVM -WindowState Centered -SkipVMVideoCheck:$SkipVMVideoCheck
    }
    
  } catch {
    $PSCmdlet.ThrowTerminatingError($_)
  }
}

Export-ModuleMember -Function Test-CTVMHostStandardVMSwitch,
                              Reset-CTVMHost,
                              Start-CTVMConnect