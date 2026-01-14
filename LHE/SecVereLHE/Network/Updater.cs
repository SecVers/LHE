using SecVerseLHE.Helper;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web;

namespace SecVerseLHE.Network
{
    internal class Updater
    {
        private static Telemetry _telemetry = new Telemetry();
        internal async static void CheckForUpdates()
        {
            if(await PerformUpdateAsync())
            {
#if !DEBUG
                BsodProtection.SetCritical(false);
#endif


            }
        }   

        private static async Task<bool> PerformUpdateAsync()
        {
          var result = await _telemetry.CheckForUpdateAsync();

          return result.updateAvailable;
        }
    }
}
