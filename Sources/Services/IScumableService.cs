namespace Gidsiks.Fail2BanService.Services
{
	/// <summary>
	/// Use to handle IP that failed enough
	/// </summary>
	/// <param name="ip">IP address that exceeds number of attempts</param>
	public delegate void FailedEnoughHandler(string ip);

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
