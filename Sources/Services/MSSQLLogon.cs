using System.Diagnostics.Eventing.Reader;
using System.Text.RegularExpressions;

namespace Gidsiks.Fail2BanService.Services
{
	internal class MSSQLLogon : IScumableService
	{
		/// <summary>
		/// This class only purpose is to store data about attempts by given IP
		/// </summary>
		class MSSQLLogonAttemptEntry
		{
			private string _ip;
			private List<string> _triedLogins;
			private int _triesCount;
			private DateTime _lastTryTime;

			/// <summary>
			/// IP that attempts to logon
			/// </summary>
			public string IP 
			{ 
				get => _ip; 
				private set => _ip = value; 
			}
			
			/// <summary>
			/// List of tried by this IP login names
			/// </summary>
			public List<string> TriedLogins
			{
				get => _triedLogins;
				private set => _triedLogins = value;
			}
			
			/// <summary>
			/// Number of attemps by this IP in a minute
			/// </summary>
			public int TriesCount
			{
				get => _triesCount;
				private set => _triesCount = value;
			}
			
			/// <summary>
			/// DateTime of last attempt to logon by this IP
			/// </summary>
			public DateTime LastTryTime
			{
				get => _lastTryTime;
				private set => _lastTryTime = value;
			}

			public MSSQLLogonAttemptEntry()
			{
				_ip = string.Empty;
				_triedLogins = new List<string>();
				_triesCount = 0;
				_lastTryTime = DateTime.MinValue;
			}

			public MSSQLLogonAttemptEntry(string ip, string login, DateTime attemptTime)
			{
				_ip = ip;
				_triedLogins = new List<string>();
				_triedLogins.Add(login);
				_triesCount = 1;
				_lastTryTime = attemptTime;
			}

			/// <summary>
			/// Increase number of attempts by this IP, store tried login and attempt time
			/// </summary>
			/// <param name="login">Tried login name</param>
			/// <param name="attemptTime">Time of new try</param>
			public void IncAttempts(string login, DateTime attemptTime)
			{
				TriesCount++;
				LastTryTime = attemptTime;
				if (!TriedLogins.Contains(login))
				{
					TriedLogins.Add(login);
				}
			}

			/// <summary>
			/// Reset Attempts by this IP to zero
			/// </summary>
			public void ResetAttempts()
			{
				TriesCount = 0;
			}
		}

		private readonly ILogger<MSSQLLogon> _logger;
		private int _maxFailedLogonCount;
		private Dictionary<string, MSSQLLogonAttemptEntry> _attemptsBy;
		private EventLogWatcher _logWatcher;

		public event FailedEnoughHandler FailedEnough;

		public MSSQLLogon()
		{
			_logger = Program.GetLogger<MSSQLLogon>();
			_logger.LogTrace("MSSQLLog Initialized");

			_maxFailedLogonCount = 3;
			_attemptsBy = new Dictionary<string, MSSQLLogonAttemptEntry>();

			EventLogQuery logQuery = new EventLogQuery("Application", PathType.LogName, "*[System[Provider[@Name='MSSQLSERVER'] and (EventID=18456)]]"); //(EventID=18452 or EventID=18456)
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
					FailedEnough(ip);
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
