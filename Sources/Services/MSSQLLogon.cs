﻿using System.Diagnostics.Eventing.Reader;
using System.Text.RegularExpressions;

namespace Gidsiks.Fail2BanService.Services
{
	internal class MSSQLLogon : IScumableService
	{
		class MSSQLLogonAttemptEntry : AttemptEntry
		{
			public MSSQLLogonAttemptEntry() : base()
			{
			}

			public MSSQLLogonAttemptEntry(string ip, string login, DateTime attemptTime) : base(ip, login, attemptTime)
			{
			}
		}

		private readonly ILogger<MSSQLLogon> _logger;
		private int _maxFailedLogonCount;
		private Dictionary<string, MSSQLLogonAttemptEntry> _attemptsBy;
		private EventLogWatcher _logWatcher;

		FailedEnoughHandler? failedEnough;
		event FailedEnoughHandler IScumableService.FailedEnough
		{
			add => failedEnough += value;
			remove => failedEnough -= value;
		}

		public MSSQLLogon()
		{
			_logger = Program.GetLogger<MSSQLLogon>();
			_logger.LogTrace("MSSQLLog Initialized");

			_maxFailedLogonCount = 3;
			_attemptsBy = new Dictionary<string, MSSQLLogonAttemptEntry>();

			var logQuery = new EventLogQuery("Application", PathType.LogName, "*[System[Provider[@Name='MSSQLSERVER'] and (EventID=18456)]]"); //(EventID=18452 or EventID=18456)
			_logWatcher = new EventLogWatcher(logQuery);
			_logWatcher.EventRecordWritten += MSSQLSERVERlogWatcher_LogRecordProcessing;
			_logWatcher.Enabled = true;
		}

		private void MSSQLSERVERlogWatcher_LogRecordProcessing(object? sender, EventRecordWrittenEventArgs e)
		{
			_logger.LogTrace("LogRecordProcessing");

			var rec = e.EventRecord;
			var recProp = rec.Properties;

			string login = (string)recProp[0].Value;
			string ip = (string)recProp[2].Value;
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
				_attemptsBy.Add(ip, new MSSQLLogonAttemptEntry(ip, login, tryTime));
			}
			else
			{
				_logger.LogInformation("Attempts to logon as [{login}] from incorrect or local IP [{ip}]", login, (string)recProp[2].Value);
			}

		}

		bool IScumableService.Check()
		{
			_logger.LogTrace("Check executed");

			return false;
		}
	}
}
