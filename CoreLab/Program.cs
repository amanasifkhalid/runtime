using System;
using System.Reflection;
using System.Diagnostics;

namespace CoreLab
{
    internal static class Program
    {
        public static void Main(string[] args)
        {
            // throw new Exception("thrown in hot code");
            try
            {
                System.Convert.FromHexString(null);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }

            Console.WriteLine("We've made it to the end!");
        }
    }
}