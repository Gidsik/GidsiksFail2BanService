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
			new MSSQLLogon(),
			new RDPLogon()
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
		/// Subscribe to all IScumableServices
		/// </summary>
		public void Start()
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
		public void BanIP(object sender, FailedEnoughEventArgs args)
		{
			_logger.LogTrace("BanIP");
			if (!FirewallManager.IsServiceRunning)
			{
				_logger.LogError("Adding to ban list failed. Windows Firewall Service is not running");
				return;
			}

			System.Net.IPAddress systemIP;// = SingleIP.Parse(ip);
			if (!System.Net.IPAddress.TryParse(args.IP, out systemIP!))
			{
				_logger.LogError("Adding to ban fist failed. Incorrect IP Address");
				return;
			}
			var singleIP = new SingleIP(systemIP);

			var rulesList = FirewallManager.Instance.Rules
				.Where(r => r.Name.Contains(FirewallRuleName));

			if (rulesList.Any())				
			{
				foreach(var rule in rulesList)
				{
					
					if (rule.RemoteAddresses.Length >= 500)
					{
						continue;
					}
					else
					{
						_logger.LogInformation("BlackList Rule already exists. Adding new ip to the BlackList");
						rule.RemoteAddresses = rule.RemoteAddresses.Append(singleIP).ToArray();
						return;
					}
				}
				_logger.LogInformation("BlackList Rule contains too many adressed. Adding new BlackList Rule");
				var newRule = CreateRule(new SingleIP[] { singleIP }, rulesList.Count() + 1);

				FirewallManager.Instance.Rules.Add(newRule);
			}
			else
			{
				_logger.LogInformation("Adding new BlackList Rule");
				var newRule = CreateRule(new SingleIP[] { singleIP });

				FirewallManager.Instance.Rules.Add(newRule);
			}

			IFirewallRule CreateRule(IAddress[] singleIPArray, int? rullNum = null)
			{
				IFirewallRule? rule = new FirewallWASRule(
								FirewallRuleName + (rullNum is null ? "" : $" #{rullNum}"),
								FirewallAction.Block,
								FirewallDirection.Inbound,
								FirewallProfiles.Domain | FirewallProfiles.Private | FirewallProfiles.Public)
				{
					RemoteAddresses = singleIPArray
				};               
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
