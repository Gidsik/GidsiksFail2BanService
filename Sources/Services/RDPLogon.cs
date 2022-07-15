using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace Gidsiks.Fail2BanService.Services
{
	internal class RDPLogon : IScumableService
	{
		class RDPLogonAttemptEntry : AttemptEntry
		{
			public RDPLogonAttemptEntry() : base()
			{
			}

			public RDPLogonAttemptEntry(string ip, string login, DateTime attemptTime) : base(ip, login, attemptTime)
			{
			}
		}

		private readonly ILogger<RDPLogon> _logger;
		private int _maxFailedLogonCount;
		private Dictionary<string, RDPLogonAttemptEntry> _attemptsBy;
		private EventLogWatcher _logWatcher;

		FailedEnoughHandler? failedEnough;
		event FailedEnoughHandler IScumableService.FailedEnough
		{
			add => failedEnough += value;
			remove => failedEnough -= value;
		}

		public RDPLogon()
		{
			_logger = Program.GetLogger<RDPLogon>();
			_logger.LogTrace("RDPLog Initialized");

			_maxFailedLogonCount = 3;
			_attemptsBy = new Dictionary<string, RDPLogonAttemptEntry>();

			EventLogQuery logQuery = new("Security", PathType.LogName, "*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and (EventID=4625)]]");
			_logWatcher = new EventLogWatcher(logQuery);
			_logWatcher.EventRecordWritten += RDPLLogonLogWatcher_LogRecordProcessing;
			_logWatcher.Enabled = true;
		}

		private void RDPLLogonLogWatcher_LogRecordProcessing(object? sender, EventRecordWrittenEventArgs e)
		{
			_logger.LogTrace("LogRecordProcessing");

			var rec = e.EventRecord;
			var recProp = rec.Properties;

			string login = $"{(String.IsNullOrEmpty((string)recProp[6].Value) ? "" : (string)recProp[6].Value + @"\")}{(string)recProp[5].Value}";
			string ip = (string)recProp[19].Value;
			Match m = Regex.Match(ip, Fail2Ban.IpRegexPattern);
			if (m.Success) { ip = m.Value; }
			else { ip = String.Empty; }
			DateTime tryTime = (rec.TimeCreated ?? DateTime.UtcNow).ToUniversalTime();


			if (_attemptsBy.ContainsKey(ip))
			{
				if ((DateTime.UtcNow - _attemptsBy[ip].LastTryTime).TotalMinutes > 1)
				{
					_logger.LogInformation("Number of login attempts for Ip [{ip}] reseted", ip);
					_attemptsBy[ip].ResetAttempts();
				}
				_attemptsBy[ip].IncAttempts(login, tryTime);
				_logger.LogInformation("Ip [{ip}] attempts to logon as [{login}] x[{times}] time", ip, login, _attemptsBy[ip].TriesCount);
				if (_attemptsBy[ip].TriesCount > _maxFailedLogonCount)
				{
					_logger.LogWarning("Ip [{ip}] has exceeded the number of login attempts in a minute", ip);
					if (failedEnough is not null) failedEnough(this, new FailedEnoughEventArgs(ip, tryTime));
				}
			}
			else if (!ip.Equals(String.Empty))
			{
				_logger.LogInformation("Ip [{ip}] attempts to logon as [{login}] x[1] time", ip, login);
				_attemptsBy.Add(ip, new RDPLogonAttemptEntry(ip, login, tryTime));
			}
			else
			{
				_logger.LogInformation("Attempts to logon as [{login}] from incorrect or local IP [{ip}]", login, (string)recProp[2].Value);
			}
		}



		bool IScumableService.Check()
		{
			_logger.LogTrace("Check executed");
			//throw new NotImplementedException();
			return false;
		}
	}
}
