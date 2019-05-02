using System;
using System.Windows.Forms;

namespace InjectExample
{
    /// <summary>
    /// Test app that can be run standalone, or using Inject.exe.
    /// </summary>
    public class Program
    {
        /// <summary>
        /// Method that matches our injection signature: 
        /// http://msdn.microsoft.com/en-us/library/ms164411.aspx
        /// </summary>
        /// <param name="pwzArgument">Optional argument to pass in.</param>
        /// <returns>An integer code defined by you.</returns>
        static int EntryPoint(String pwzArgument)
        {
            // show modal message box
            MessageBox.Show(
                "I am a managed app.\n\n" +
                "I am running inside: [" + System.Diagnostics.Process.GetCurrentProcess().ProcessName + "]\n\n" +
                (String.IsNullOrEmpty(pwzArgument) ? "I was not given an argument" : "I was given this argument: [" + pwzArgument + "]"));

            return 0;
        }

        /// <summary>
        /// Main method. Invoked when app is run standalone.
        /// </summary>
        /// <param name="args"></param>
        static void Main(string[] args)
        {
            EntryPoint("hello world");
        }
    }
}
