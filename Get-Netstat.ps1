$TypeDefinition=@"
  using System;
  using System.Runtime.InteropServices;
  using System.Collections;
  using System.Collections.Generic;
  using System.Linq;
  
  // https://msdn2.microsoft.com/en-us/library/aa366073.aspx
  namespace IPHelper {

      // https://msdn2.microsoft.com/en-us/library/aa366913.aspx
      [StructLayout(LayoutKind.Sequential)]
      public struct MIB_TCPROW_OWNER_PID {
      public uint state;
      public uint localAddr;
      [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
      public byte[] localPort;
      public uint remoteAddr;
      [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
      public byte[] remotePort;
      public uint owningPid;
      }

      // https://msdn2.microsoft.com/en-us/library/aa366921.aspx
      [StructLayout(LayoutKind.Sequential)]
      public struct MIB_TCPTABLE_OWNER_PID {
      public uint dwNumEntries;
      [MarshalAs(UnmanagedType.ByValArray, ArraySubType = UnmanagedType.Struct, SizeConst = 1)]
      public MIB_TCPROW_OWNER_PID[] table;
       }

      // https://msdn.microsoft.com/en-us/library/aa366896
      [StructLayout(LayoutKind.Sequential)]
      public struct MIB_TCP6ROW_OWNER_PID {
      [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
      public byte[] localAddr;
      public uint localScopeId;
      [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
      public byte[] localPort;
      [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
      public byte[] remoteAddr;
      public uint remoteScopeId;
      [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
      public byte[] remotePort;
      public uint state;
      public uint owningPid;
      }

      // https://msdn.microsoft.com/en-us/library/windows/desktop/aa366905
      [StructLayout(LayoutKind.Sequential)]
      public struct MIB_TCP6TABLE_OWNER_PID {
     public uint dwNumEntries;
     [MarshalAs(UnmanagedType.ByValArray, ArraySubType = UnmanagedType.Struct, SizeConst = 1)]
     public MIB_TCP6ROW_OWNER_PID[] table;
      }

      // https://msdn2.microsoft.com/en-us/library/aa366386.aspx
      public enum TCP_TABLE_CLASS {
      TCP_TABLE_BASIC_LISTENER,
      TCP_TABLE_BASIC_CONNECTIONS,
      TCP_TABLE_BASIC_ALL,
      TCP_TABLE_OWNER_PID_LISTENER,
      TCP_TABLE_OWNER_PID_CONNECTIONS,
      TCP_TABLE_OWNER_PID_ALL,
      TCP_TABLE_OWNER_MODULE_LISTENER,
      TCP_TABLE_OWNER_MODULE_CONNECTIONS,
      TCP_TABLE_OWNER_MODULE_ALL
      }

      // https://msdn.microsoft.com/en-us/library/aa366896.aspx
      public enum MIB_TCP_STATE {
      MIB_TCP_STATE_CLOSED,
      MIB_TCP_STATE_LISTEN,
      MIB_TCP_STATE_SYN_SENT,
      MIB_TCP_STATE_SYN_RCVD,
      MIB_TCP_STATE_ESTAB,
      MIB_TCP_STATE_FIN_WAIT1,
      MIB_TCP_STATE_FIN_WAIT2,
      MIB_TCP_STATE_CLOSE_WAIT,
      MIB_TCP_STATE_CLOSING,
      MIB_TCP_STATE_LAST_ACK,
      MIB_TCP_STATE_TIME_WAIT,
      MIB_TCP_STATE_DELETE_TCB
      }

      public static class IPHelperAPI {
      [DllImport("iphlpapi.dll", SetLastError = true)]
      internal static extern uint GetExtendedTcpTable(
          IntPtr tcpTable,
          ref int tcpTableLength,
          bool sort,
          int ipVersion,
          TCP_TABLE_CLASS tcpTableType,
          int reserved=0);
      }

      public class IPHelperWrapper : IDisposable {

      public const int AF_INET = 2;    // IP_v4 = System.Net.Sockets.AddressFamily.InterNetwork
      public const int AF_INET6 = 23;  // IP_v6 = System.Net.Sockets.AddressFamily.InterNetworkV6

      // Creates a new wrapper for the local machine
      public IPHelperWrapper() { }

      // Disposes of this wrapper
      public void Dispose() { GC.SuppressFinalize(this); }

      public List<MIB_TCPROW_OWNER_PID> GetAllTCPv4Connections() {
          return GetTCPConnections<MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID>(AF_INET);
      }

      public List<MIB_TCP6ROW_OWNER_PID> GetAllTCPv6Connections() {
          return GetTCPConnections<MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID>(AF_INET6);
      }

      public List<IPR> GetTCPConnections<IPR, IPT>(int ipVersion) { //IPR = Row Type, IPT = Table Type

          IPR[] tableRows;
          int buffSize = 0;
          var dwNumEntriesField = typeof(IPT).GetField("dwNumEntries");

          // how much memory do we need?
          uint ret = IPHelperAPI.GetExtendedTcpTable(IntPtr.Zero, ref buffSize, true, ipVersion, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL);
          IntPtr tcpTablePtr = Marshal.AllocHGlobal(buffSize);

          try {
          ret = IPHelperAPI.GetExtendedTcpTable(tcpTablePtr, ref buffSize, true, ipVersion, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL);
          if (ret != 0) return new List<IPR>();

          // get the number of entries in the table
          IPT table = (IPT)Marshal.PtrToStructure(tcpTablePtr, typeof(IPT));
          int rowStructSize = Marshal.SizeOf(typeof(IPR));
          uint numEntries = (uint)dwNumEntriesField.GetValue(table);

          // buffer we will be returning
          tableRows = new IPR[numEntries];

          IntPtr rowPtr = (IntPtr)((long)tcpTablePtr + 4);
          for (int i = 0; i < numEntries; i++) {
              IPR tcpRow = (IPR)Marshal.PtrToStructure(rowPtr, typeof(IPR));
              tableRows[i] = tcpRow;
              rowPtr = (IntPtr)((long)rowPtr + rowStructSize);   // next entry
          }
          }
          finally {
          // Free the Memory
          Marshal.FreeHGlobal(tcpTablePtr);
          }
          return tableRows != null ? tableRows.ToList() : new List<IPR>();
      }

      // Occurs on destruction of the Wrapper
      ~IPHelperWrapper() { Dispose(); }

      } // wrapper class
  } // namespace
"@
  Add-Type -TypeDefinition $TypeDefinition -PassThru | Out-Null
 function reverseIP([string]$arg1) { 
    $arglist = $arg1.split('.') 
	$arg1 = $null 
	for($i = $arglist.Length - 1; $i -ge 0; $i--) { 
	   $arg1+=$arglist[$i]
	   $arg1+='.'
	}
	$arg1 = $arg1.TrimEnd('.')
	return $arg1
	
	}
	   
 function Get-Netstat {  
 $iphlp=New-Object IPHelper.IPHelperWrapper
 $tcp_comms = $iphlp.GetAllTCPv4Connections() 
 $StateList=@("UNKNOWN","CLOSED","LISTEN","SYN-SENT","SYN-RECEIVED","ESTABLISHED","FIN-WAIT-1","FIN-WAIT-2","CLOSE-WAIT","CLOSING","LAST-ACK","TIME-WAIT","DELETE-TCB")
 $output=@()
 for ($i=0; $i -lt $tcp_comms.Count; $i++) {
      $objOutput=New-Object -TypeName PSObject
      Add-Member -InputObject $objOutput -MemberType NoteProperty -Name "LocalAddress" -Value (reverseIp([System.Net.IPAddress]::parse($tcp_comms[$i].localAddr).IPAddressToString))
      Add-Member -InputObject $objOutput -MemberType NoteProperty -Name "RemoteAddress" -Value (reverseIp([System.Net.IPAddress]::parse($tcp_comms[$i].remoteAddr).IPAddressToString))
      Add-Member -InputObject $objOutput -MemberType NoteProperty -Name "LocalPort" -Value ($tcp_comms[$i].localPort[1]+($tcp_comms[$i].localPort[0]*0x100)+($tcp_comms[$i].localPort[3]*0x1000)+($tcp_comms[$i].localPort[2]*0x10000))
      Add-Member -InputObject $objOutput -MemberType NoteProperty -Name "RemotePort" -Value ($tcp_comms[$i].remotePort[1]+($tcp_comms[$i].remotePort[0]*0x100)+($tcp_comms[$i].remotePort[3]*0x1000)+($tcp_comms[$i].remotePort[2]*0x10000))
      Add-Member -InputObject $objOutput -MemberType NoteProperty -Name "PID" -Value $tcp_comms[$i].owningPid
      Add-Member -InputObject $objOutput -MemberType NoteProperty -Name "ProcessName" -Value ((Get-Process -Id $tcp_comms[$i].owningPid).ProcessName)
      Add-Member -InputObject $objOutput -MemberType NoteProperty -Name "StateValue" -Value $tcp_comms[$i].state
      Add-Member -InputObject $objOutput -MemberType NoteProperty -Name "State" -Value $StateList[$tcp_comms[$i].state]
	  
      $output+=$objOutput
}



for ($i=0; $i -lt $output.Length; $i++) { 
   if (($output[$i].State -ne "LISTEN")) {
   Write-Host $output[$i].LocalAddress $output[$i].LocalPort $output[$i].RemoteAddress $output[$i].RemotePort $output[$i].PID $output[$i].ProcessName $output[$i].State | Format-Table
}
   else {
   Write-Host  $output[$i].LocalAddress $output[$i].LocalPort $output[$i].PID $output[$i].ProcessName $output[$i].State | Format-Table
}
Write-Host " "
}

}

