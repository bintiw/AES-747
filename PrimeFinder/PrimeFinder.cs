using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;

namespace SieveAlgorithm
{
    class Program
    {
        static void Main(string[] args)
        {
            
            Console.WriteLine("Enter upper limit to find prime number:");
            string pr = Console.ReadLine();
            int i = 0;
            int j = 0;
            int step = 0;
            List<int> a = new List<int>();
            int n = Convert.ToInt32(pr);
            Console.WriteLine("Generating Numbers..");
            for (i = 2; i < n + 1; i = i + 1)
            {
                a.Add(i);
            }
            
                
            i = 0;
            Console.WriteLine("Finding Primes..");
            while (i < (int)(Math.Sqrt(n)))
            {
                if (a[i] != 0)
                {
                    j = i;
                    step = a[i];
                    while (j < a.Count)
                    {
                        a[j] = 0;
                        j = j + step;

                    }
                    a[i] = step;
                }


                i = i + 1;

            }


            a.RemoveAll(item => item == 0);

            Console.WriteLine("Total Primes:" + a.Count);
            Console.WriteLine("Preparing to Write Primes..");

            StringBuilder builder = new StringBuilder();
            builder.Append("Total Prime from 0 to" + ' ' + n + ' ' + ":" + ' ' + a.Count + '\r' + '\n');
            foreach (int safePrime in a)
            {

                builder.Append(safePrime).Append('\r').Append('\n');

            }
            string result = builder.ToString();

            Console.WriteLine("Writing in File..");

            string filename = System.IO.Path.GetFullPath(Directory.GetCurrentDirectory() + @"\prime_list.txt");
            System.IO.File.WriteAllText(filename, result);

            Console.WriteLine("Success..");
            Console.ReadKey();
        }
    }
}
