using System;
using System.Collections.Generic;
using System.Text;
using Utility;

namespace Utility
{
/***********************************************
 *  This is a simple Wrapper over CommandLine.cs
 ***********************************************/
    public class CmdArgs
    {
        public string FirstArgs;
        public CommandArgs CommandArg;
    }

    public class CmdLinePraser
    {
        //Init
        public static CmdArgs CmdLinePrase(string[] args)
        {
            CmdArgs cmdarg = new CmdArgs();
            cmdarg.FirstArgs = args[0];
            cmdarg.CommandArg = CommandLine.Parse(args);
            return cmdarg;
        }
    }

}
