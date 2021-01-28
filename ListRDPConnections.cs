﻿using System;
using Microsoft.Win32;
using Microsoft.VisualBasic.Devices;
using System.IO;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Xml;
using System.Linq;

class ListRDPConnections
{
	private static RegistryKey rk;
	private static string prefix = @"C:\Users\";

	private class Out
	{
		public string port;
		public string username;

		public Out(string v1, string v2)
		{
			port = v1;
			username = v2;
		}
	}

	private class Info
	{
		public int num;
		public string lastTime;

		public Info(int v1, string v2)
		{
			num = v1;
			lastTime = v2;
		}
	}

	static void ListRDPOutConnections()
	{
		Console.WriteLine("RDP外连:");

		List<string> sids = new List<string>(Registry.Users.GetSubKeyNames());
		
		// Load NTUSER.DAT
		foreach (string dic in Directory.GetDirectories(prefix))
		{
			try
			{
				string subkey = "S-123456789-" + dic.Replace(prefix, "");
				string sid = RegistryInterop.Load(subkey, $@"{dic}\NTUSER.DAT");
				sids.Add(sid);
			}
			catch
			{
				continue;
			}
		}

		// Dump RDP Connection History From Registry
		foreach (string sid in sids)
		{
			if (!sid.StartsWith("S-") || sid.EndsWith("Classes") || sid.Length < 10)
				continue;

			Dictionary<string, Out> history = GetRegistryValues(sid);
			PrintRDPOutHistory(history, sid);

			if (sid.StartsWith("S-123456789-"))
			{
				UnLoadHive(sid);
			}
		}

		// Dump RDP Connection History From RDP Files
		foreach (string dic in Directory.GetDirectories(prefix))
		{
			try
			{
				foreach (string file in Directory.GetFiles($@"{dic}\Documents\", "*.rdp"))
				{
					Dictionary<string, Out> history = GetRdpFileValues(file);
					PrintRDPOutHistory(history, file);
				}
			}
			catch
			{
				continue;
			}
		}
	}

	static void PrintRDPOutHistory(Dictionary<string, Out> values, string sid = "")
	{
		if (values.Count != 0)
		{
			Console.WriteLine($"{sid}:");
			foreach (var item in values)
			{
				string port = item.Value.port != "" ? ":" + item.Value.port : "";
				Console.WriteLine($"{item.Key}{port}\t{item.Value.username}");
			}
			Console.WriteLine();
		}
	}

	static void UnLoadHive(string sid)
	{
		if (sid.StartsWith("S-123456789-"))
		{
			RegistryInterop.UnLoad(sid);
		}
	}

	static string GetOSName()
	{
		return new ComputerInfo().OSFullName;
	}

	static Dictionary<string, Out> GetRegistryValues(string sid)
	{
		Dictionary<string, Out> values = new Dictionary<string, Out>();
		string baseKey = $@"{sid}\Software\Microsoft\Terminal Server Client\";

		try
		{
			// Default
			rk = Registry.Users.OpenSubKey(baseKey + "Default");
			foreach (string mru in rk.GetValueNames())
			{
				string port = "";
				string value = rk.GetValue(mru).ToString();
				string address = value.Split(':')[0];
				if (value.Contains(":"))
				{
					port = value.Split(':')[1];
				}
				values.Add(address, new Out(port, ""));
			}
			rk.Close();

			// Servers
			rk = Registry.Users.OpenSubKey(baseKey + "Servers");
			string[] addresses = rk.GetSubKeyNames();
			rk.Close();
			foreach (string address in addresses)
			{
				rk = Registry.Users.OpenSubKey($@"{baseKey}Servers\{address}");
				string user = rk.GetValue("UsernameHint").ToString();
				if (values.ContainsKey(address))
				{
					values[address].username = user;
				}
				rk.Close();
			}
		}
		catch
		{
		}

		return values;
	}

	static Dictionary<string, Out> GetRdpFileValues(string file)
	{
		Dictionary<string, Out> values = new Dictionary<string, Out>();
		string line;
		string addressStr = "full address:s:";
		string usernameStr = "username:s:";
		string address = "";
		string username = "";
		string port = "";

		try
		{
			StreamReader sr = new StreamReader(file);
			while (sr.Peek() >= 0)
			{
				line = sr.ReadLine();
				if (line.StartsWith(addressStr))
				{
					address = line.Replace(addressStr, "");
				}
				if (line.StartsWith(usernameStr))
				{
					username = line.Replace(usernameStr, "");
				}
			}
						
			if (address != "")
			{
				address = address.Split(':')[0];
				if (address.Contains(":"))
				{
					port = address.Split(':')[1];
				}
				values.Add(address, new Out(port, username));
			}
		}
		catch
		{
		}

		return values;
	}

	static void ListRDPInConnections()
	{
		Console.WriteLine("RDP内连:");

		string logTypeSuccess = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational";
		string logTypeAll = "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational";
		string querySuccess = "*[System/EventID=21] or *[System/EventID=25]";
		string queryAll = "*[System/EventID=1149]";

		var historySuccess = ListEventvwrRecords(logTypeSuccess, querySuccess).OrderByDescending(s => s.Value.num).ToDictionary(p => p.Key, p => p.Value);
		var historyAll = ListEventvwrRecords(logTypeAll, queryAll, true).OrderByDescending(s => s.Value.num).ToDictionary(p => p.Key, p => p.Value);

		Console.WriteLine("Login Successful:");
		foreach (var item in historySuccess)
		{
			Console.WriteLine($"{item.Value.lastTime}  {item.Value.num}\t{item.Key}");
			historyAll.Remove(item.Key);
		}

		Console.WriteLine("Login Failed:");
		foreach (var item in historyAll)
		{
			Console.WriteLine($"{item.Value.lastTime}  {item.Value.num}\t{item.Key}");
		}
	}

	static Dictionary<string, Info> ListEventvwrRecords(string logType, string query, bool flag=false)
	{
		Dictionary<string, Info> values = new Dictionary<string, Info>();

		var elQuery = new EventLogQuery(logType, PathType.LogName, query);
		var elReader = new EventLogReader(elQuery);

		for (EventRecord eventInstance = elReader.ReadEvent(); eventInstance != null; eventInstance = elReader.ReadEvent())
		{
			XmlDocument doc = new XmlDocument();
			doc.LoadXml(eventInstance.ToXml());
			XmlNodeList systemData = doc.FirstChild.FirstChild.ChildNodes;
			XmlNodeList userData = doc.FirstChild.LastChild.FirstChild.ChildNodes;
			string lastTime = systemData[7].Attributes.Item(0).InnerText.Remove(19);
			string user = userData[0].InnerText;
			string address = userData[2].InnerText;

			if (flag == true)
			{
				string domain = userData[1].InnerText;
				user = domain + (domain != "" ? "\\" : "")  + user;
			}
			string value = $"{address}\t{user}";

			if (address != "本地")
			{
				if (!values.ContainsKey(value))
				{
					values.Add(value, new Info(1, lastTime));
				}
				else
				{
					values[value].num += 1;
				}
			}
		}

		return values;
	}

	static void Main(string[] args)
	{
		Console.WriteLine("Author: HeartSky");
		Console.WriteLine();

		ListRDPOutConnections();
		ListRDPInConnections();
	}
}
