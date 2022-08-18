using Gidsiks.Fail2BanService.Services;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading.Tasks;

namespace Gidsiks.Fail2BanService.Settings
{
	[Serializable]
	internal class ServiceSettings
	{
		public int? MaxFailedAttempts { get; set; }
		public int? MinsBeforeReset { get; set; }

		public ServiceSettings()
		{
		}

		public ServiceSettings(bool useDefaults)
		{
			if (useDefaults)
			{
				MaxFailedAttempts = 5;
				MinsBeforeReset = 1;
			}
		}

		public ServiceSettings(int maxFailedLogons, int timeBeforeReset)
		{
			MaxFailedAttempts = maxFailedLogons;
			MinsBeforeReset = timeBeforeReset;
		}
	}

	[Serializable]
	internal class FTPSettings : ServiceSettings
	{
		public string? JournalPath { get; set; }

		public FTPSettings() 
		{ 
		}

		public FTPSettings(int MaxFailedAttempts, int MinsBeforeReset, string JournalPath) : base(MaxFailedAttempts, MinsBeforeReset)
		{
			this.JournalPath = JournalPath;
		}
	}

	internal class Settings
	{
		public ServiceSettings? DefaultSettings { get; set; }
		public ServiceSettings? MSSQLLogonSettings { get; set; }
		public ServiceSettings? RDPLogonSettings { get; set; }
		public FTPSettings? FTPLogonSettings { get; set; }
	}


	internal class SettingsManager
	{
		private static readonly ILogger<SettingsManager> _logger = Program.GetLogger<SettingsManager>();

		private static readonly string settingsDirectory = $"{Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)}" +
				$"\\{typeof(Program).Assembly.GetCustomAttributes<AssemblyCompanyAttribute>().First().Company}" +
				$"\\{typeof(Program).Assembly.GetName().Name}";

		private static readonly string settingsFileName = settingsDirectory +
				$"\\Settings.json";

		private static readonly string defaultsJsonString =
@"
{
	""Settings"": {
		""Default"": {
			""MaxFailedAttempts"": 5,
			""MinsBeforeReset"": 1
		}
	}
}
";

		private static JsonNode settingsJson = default!;

		public static Settings Settings { get; private set; } = new Settings();

		public static Dictionary<string, ServiceSettings> SettingsDict { get; private set; } = new Dictionary<string, ServiceSettings>();

		public static void LoadSettings()
		{
			_logger.LogTrace("LoadSettings()");

			if (!Directory.Exists(settingsDirectory) || !File.Exists(settingsFileName))
			{
				InitSettingsStore();
			}

			string rawData = File.ReadAllText(settingsFileName);

			JsonNode tempSettings;
			JsonNode? settingsNode;

			try
			{
				tempSettings = JsonNode.Parse(rawData)!; 
				if (tempSettings["Settings"] == null)
				{
					throw new Exception("Settings not found");
				}
			}
			catch (Exception e)
			{
				_logger.LogError("Error parsing Settings.json, using defaults. Error: {Message}", e.Message);
				tempSettings = JsonNode.Parse(defaultsJsonString)!;
			}
			settingsNode = tempSettings[nameof(Settings)]!;


			if (settingsNode["DefaultSettings"] is null)
			{
				Settings.DefaultSettings = new ServiceSettings(true);
				SettingsDict["DefaultSettings"] = new ServiceSettings(true);
			}
			else
			{
				try
				{
					Settings.DefaultSettings = JsonSerializer.Deserialize<ServiceSettings>(settingsNode["DefaultSettings"]);
					SettingsDict["DefaultSettings"] = JsonSerializer.Deserialize<ServiceSettings>(settingsNode["DefaultSettings"])!;
				}
				catch (Exception e)
				{
					_logger.LogError("Error parsing DefaultSettings, using defaults. Error: {Message}", e.Message);
					Settings.DefaultSettings = new ServiceSettings(true);
				}
			}

			if (settingsNode["MSSQLLogonSettings"] is not null)
			{
				try
				{
					Settings.MSSQLLogonSettings = JsonSerializer.Deserialize<ServiceSettings>(settingsNode["MSSQLLogonSettings"]);
					SettingsDict["MSSQLLogonSettings"] = JsonSerializer.Deserialize<ServiceSettings>(settingsNode["MSSQLLogonSettings"])!;
				}
				catch (Exception e)
				{
					_logger.LogError("Error parsing MSSQLLogonSettings. Error: {Message}", e.Message);
				}
			}

			if (settingsNode["RDPLogonSettings"] is not null)
			{
				try
				{
					Settings.RDPLogonSettings = JsonSerializer.Deserialize<ServiceSettings>(settingsNode["RDPLogonSettings"]);
					SettingsDict["RDPLogonSettings"] = JsonSerializer.Deserialize<ServiceSettings>(settingsNode["RDPLogonSettings"])!;
				}
				catch (Exception e)
				{
					_logger.LogError("Error parsing RDPLogonSettings. Error: {Message}", e.Message);
				}
			}

			if (settingsNode["FTPLogonSettings"] is not null)
			{
				try { 
				Settings.FTPLogonSettings = JsonSerializer.Deserialize<FTPSettings>(settingsNode["FTPLogonSettings"]);
					SettingsDict["FTPLogonSettings"] = JsonSerializer.Deserialize<FTPSettings>(settingsNode["FTPLogonSettings"])!;
				}
				catch (Exception e)
				{
					_logger.LogError("Error parsing FTPLogonSettings. Error: {Message}", e.Message);
				}
			}
			settingsJson = tempSettings;
		}

		public static void StoreSettings()
		{
			_logger.LogTrace("StoreSettings()");

			var options = new JsonSerializerOptions { WriteIndented = true };

			var settingsNode = settingsJson[nameof(Settings)]!;

			settingsNode["DefaultSettings"] = JsonNode.Parse(JsonSerializer.Serialize(Settings.DefaultSettings, options));

			settingsNode["MSSQLLogonSettings"] = JsonNode.Parse(JsonSerializer.Serialize(Settings.MSSQLLogonSettings, options));

			settingsNode["RDPLogonSettings"] = JsonNode.Parse(JsonSerializer.Serialize(Settings.RDPLogonSettings, options));

			settingsNode["FTPLogonSettings"] = JsonNode.Parse(JsonSerializer.Serialize(Settings.FTPLogonSettings, options));


			var serializedData = settingsJson.ToJsonString(options);
			File.WriteAllText(settingsFileName, serializedData);
		}

		private static void InitSettingsStore()
		{
			_logger.LogTrace("InitSettingsStore()");
			if (!Directory.Exists(settingsDirectory))
			{
				Directory.CreateDirectory(settingsDirectory);
			}

			File.WriteAllText(settingsFileName, defaultsJsonString);
		}
	}
}
