namespace Gidsiks.Fail2BanService.Services
{

	/// <summary>
	/// This class only purpose is to store data about attempts by given IP
	/// </summary>
	public class AttemptEntry
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

		public AttemptEntry()
		{
			_ip = string.Empty;
			_triedLogins = new List<string>();
			_triesCount = 0;
			_lastTryTime = DateTime.MinValue;
		}

		public AttemptEntry(string ip, string login, DateTime attemptTime)
		{
			_ip = ip;
			_triedLogins = new List<string>() { login };
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

	/// <summary>
	/// Contains event data for FailedEnough event
	/// </summary>
	public class FailedEnoughEventArgs : EventArgs
	{
		/// <summary>
		/// IP address that exceeds number of attempts
		/// </summary>
		public readonly string IP;

		/// <summary>
		/// Time when IP exceeds number of attempts
		/// </summary>
		public readonly DateTime Time;

		/// <param name="ip">IP address that exceeds number of attempts</param>
		/// <param name="time">Time when IP exceeds number of attempts</param>
		public FailedEnoughEventArgs(string ip, DateTime time)
		{
			IP = ip;
			Time = time;
		}
	}

	/// <summary>
	/// Use to handle IP that failed enough
	/// </summary>
	/// <param name="sender">IScumableService that raises event</param>
	/// <param name="args">IP address that exceeds number of attempts</param>
	public delegate void FailedEnoughHandler(object sender, FailedEnoughEventArgs args);

	/// <summary>
	/// Interface for services\applications that needs fail2ban protection
	/// </summary>
	interface IScumableService
	{
		public bool Check();

		/// <summary>
		/// Event That raises when IP adress exceeds number of attempts in a minute
		/// </summary>
		public event FailedEnoughHandler FailedEnough;
	}
}
