using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Threading.Channels;
using System.Net.Sockets;

namespace tcpScannerWChannels
{
    class Program
    {
        static void Main(string[] args)
        {
            var watch = new System.Diagnostics.Stopwatch();
            watch.Start();
            var target = "scanme.nmap.org";
            if (args.Length == 2)
                target = args[1];

            Console.WriteLine($"Running scan against {target}");

            var results = RunScan(target, 10000).Result;

            Console.WriteLine($"The following ports are open on {target}");

            watch.Stop();
            foreach (var port in results)
                Console.WriteLine($"port {port} is open");

            Console.WriteLine($"Scan of {target} completed in {watch.Elapsed}");
        }


        public static async Task<List<int>> RunScan(string target, int jobs = 10)
        {
            //setup scanning channel
            var scanChannel = Channel.CreateBounded<int>(new BoundedChannelOptions(1000)
            {
                FullMode = BoundedChannelFullMode.Wait,
                SingleReader = false,
                SingleWriter = true
            });

            //setup results channel
            var resultsChannel = Channel.CreateBounded<int>(new BoundedChannelOptions(2000)
            {
                FullMode = BoundedChannelFullMode.Wait,
                SingleReader = true,
                SingleWriter = false
            });

            //Create the processor task
            var resultsTask = Task.Run(() => ProcessResults(resultsChannel.Reader));

            //create checkers
            var portCheckerTasks = new List<Task>();

            for (int i = 0; i < jobs; i++)
            {
                portCheckerTasks.Add(Task.Run(() => CheckPort(target, scanChannel.Reader, resultsChannel.Writer)));
            }

            for (int i = 0; i <= 100; i++)
                scanChannel.Writer.TryWrite(i);

            scanChannel.Writer.Complete();

            //wait for all the scanners to finish up
            await scanChannel.Reader.Completion;
            await Task.WhenAll(portCheckerTasks);

            return resultsTask.Result;
        }

        public static async Task CheckPort(string target, ChannelReader<int> portChannel, ChannelWriter<int> outputWriter)
        {
            TcpClient client = new TcpClient();
            //wait while channel is open
            while (await portChannel.WaitToReadAsync())
            {
                while (portChannel.TryRead(out var message))
                {
                    try
                    {
                        client = new TcpClient(target, message);
                    }
                    catch
                    {
                        continue;
                    }
                    finally
                    {
                        try
                        {
                            client.Close();
                        }
                        catch { }
                    }
                    outputWriter.TryWrite(message);
                }
            }
            client.Close();
            client.Dispose();
            outputWriter.TryComplete();
        }

        public static async Task<List<int>> ProcessResults(ChannelReader<int> resultsReader)
        {
            var output = new List<int>();
            while (await resultsReader.WaitToReadAsync())
            {
                if (resultsReader.TryRead(out var port))
                {
                    output.Add(port);
                }
            }

            return output;
        }
    }
}
