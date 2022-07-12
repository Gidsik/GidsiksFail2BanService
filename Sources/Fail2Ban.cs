using Gidsiks.Fail2BanService.Services;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using WindowsFirewallHelper;
using WindowsFirewallHelper.Addresses;
using WindowsFirewallHelper.FirewallRules;

namespace Gidsiks.Fail2BanService
{
	/// <summary>
	/// Main class that listens to the given services events and operates WindowsFirewall
	/// </summary>
	internal class Fail2Ban
	{
		public const string FirewallRuleName = @"GidsiksFail2Ban BlackList";
		public static string IpRegexPattern = "((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\\.|$|)){4}";

		private readonly ILogger<Fail2Ban> _logger = Program.GetLogger<Fail2Ban>();

		List<IScumableService> fail2banServices = new() 
		{ 
			new MSSQLLogon()
		};

		/// <summary>
		/// Constructor subscribes to all IScumableServices
		/// </summary>
		public Fail2Ban()
		{
			foreach (var service in fail2banServices)
			{
				service.FailedEnough += BanIP;
			}
		}

		/// <summary>
		/// Unsubscribe from all IScumableServices
		/// </summary>
		public void Stop()
		{
			foreach (var service in fail2banServices)
			{
				service.FailedEnough -= BanIP;
			}
		}


		/// <summary>
		/// Adds given IP address to the firewall blacklist rule
		/// </summary>
		/// <param name="ip">IP address to BAN</param>
		public void BanIP(string ip)
		{
			_logger.LogTrace("BanIP");
			if (!FirewallManager.IsServiceRunning)
			{
				_logger.LogError("Adding to ban list failed. Windows Firewall Service is not running");
				return;
			}

			System.Net.IPAddress systemIP;// = SingleIP.Parse(ip);
			if (!System.Net.IPAddress.TryParse(ip, out systemIP!))
			{
				_logger.LogError("Adding to ban fist failed. Incorrect IP Address");
				return;
			}
			SingleIP singleIP = new SingleIP(systemIP);

			var rule = FirewallManager.Instance.Rules
				.SingleOrDefault(r => r.Name.Equals(FirewallRuleName));

			if (rule is not null)				
			{
				_logger.LogInformation("BlackList Rule already exists. Adding new ip to the BlackList");

				rule.RemoteAddresses = rule.RemoteAddresses.Append(singleIP).ToArray();
			}
			else
			{
				_logger.LogInformation("Adding new BlackList Rule");
				rule = CreateRule(new SingleIP[] { singleIP });

				FirewallManager.Instance.Rules.Add(rule);
			}

			IFirewallRule CreateRule(IAddress[] singleIPArray)
			{
				IFirewallRule? rule = new FirewallWASRule(
								FirewallRuleName,
								FirewallAction.Block,
								FirewallDirection.Inbound,
								FirewallProfiles.Domain | FirewallProfiles.Private | FirewallProfiles.Public);
				rule.RemoteAddresses = singleIPArray;
				return rule;
			}
		}

		public void Check()
		{
			_logger.LogTrace("Check executed");
			foreach (var service in fail2banServices)
			{
				service.Check();
			}
		}

	}
}
