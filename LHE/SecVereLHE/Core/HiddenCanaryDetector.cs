using SecVerseLHE.Helper;
using SecVerseLHE.UI;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;

namespace SecVerseLHE.Core
{
    internal class HiddenCanaryDetector : ThreadManager.IManagedThreadWorker, IDisposable
    {
        private const string CanaryFolderName = "SuperDuper_secure_Passwords_101";
        private const string CanaryFileName = "cool.txt";
        private const string CanaryFileContents = "If you can read this, you found a canary file.";
        private const int CanaryRefreshIntervalMs = 15000;

        private static readonly HashSet<string> SafeProcesses = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "explorer", "searchindexer", "msiexec", "trustedinstaller",
            "tiworker", "windows.immersiveshell", "runtimebroker",
            "onedrive", "dropbox", "googledrivesync",
            "system", "idle", "csrss", "smss", "wininit",
            "svchost", "services", "lsass", "dwm", "taskhostw",
            "secverselhe", "secverse"
        };

        private readonly TrayMessageDispatcher _dispatcher;
        private readonly List<FileSystemWatcher> _watchers;
        private readonly HashSet<string> _canaryPaths;
        private readonly object _watcherLock = new object();
        private readonly object _canaryLock = new object();
        private readonly ConcurrentDictionary<string, DateTime> _recentAlerts;

        private CancellationToken _cancellationToken;
        private volatile bool _disposed;
        private volatile bool _isRunning;
        private volatile bool _suppressEvents;

        public HiddenCanaryDetector(TrayMessageDispatcher dispatcher)
        {
            _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));
            _watchers = new List<FileSystemWatcher>();
            _canaryPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _recentAlerts = new ConcurrentDictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
        }

        public void Initialize(CancellationToken token)
        {
            _cancellationToken = token;
            EnsureCanaryFiles();
            InitializeWatchers();
        }

        public void Execute()
        {
            _isRunning = true;
            while (!_cancellationToken.IsCancellationRequested)
            {
                try
                {
                    EnsureCanaryFiles();
                    CleanupAlertCache();
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"LHE HiddenCanaryDetector: Loop error: {ex.Message}");
                }

                try
                {
                    Thread.Sleep(CanaryRefreshIntervalMs);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch
                {
                }
            }
            _isRunning = false;
        }

        public void Cleanup()
        {
            _isRunning = false;
            DisposeWatchers();
        }

        public void OnError(Exception ex)
        {
            try
            {
                _dispatcher.Enqueue("Canary Detector Error",
                    $"Canary monitoring error: {ex?.Message ?? "Unknown"}");
            }
            catch
            {
            }
        }

        private void EnsureCanaryFiles()
        {
            if (_disposed || _cancellationToken.IsCancellationRequested)
                return;

            var baseFolders = GetBaseFolders();
            if (baseFolders.Count == 0)
                return;

            _suppressEvents = true;
            try
            {
                foreach (var folder in baseFolders)
                {
                    if (string.IsNullOrWhiteSpace(folder) || !Directory.Exists(folder))
                        continue;

                    var canaryFolderPath = Path.Combine(folder, CanaryFolderName);
                    var canaryFilePath = Path.Combine(canaryFolderPath, CanaryFileName);

                    try
                    {
                        if (!Directory.Exists(canaryFolderPath))
                        {
                            Directory.CreateDirectory(canaryFolderPath);
                        }

                        ApplyHiddenSystemAttributes(canaryFolderPath);

                        if (!File.Exists(canaryFilePath))
                        {
                            File.WriteAllText(canaryFilePath, CanaryFileContents);
                        }

                        ApplyHiddenSystemAttributes(canaryFilePath);

                        lock (_canaryLock)
                        {
                            _canaryPaths.Add(canaryFolderPath);
                            _canaryPaths.Add(canaryFilePath);
                        }
                    }
                    catch (Exception ex)
                    {
                        Debug.WriteLine($"LHE HiddenCanaryDetector: Failed to ensure canary at {folder}: {ex.Message}");
                    }
                }
            }
            finally
            {
                _suppressEvents = false;
            }
        }

        private static void ApplyHiddenSystemAttributes(string path)
        {
            try
            {
                var attributes = File.GetAttributes(path);
                attributes |= FileAttributes.Hidden | FileAttributes.System | FileAttributes.NotContentIndexed;
                File.SetAttributes(path, attributes);
            }
            catch
            {
            }
        }

        private List<string> GetBaseFolders()
        {
            var baseFolders = new List<string>();

            try
            {
                var desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
                if (!string.IsNullOrWhiteSpace(desktop)) baseFolders.Add(desktop);
            }
            catch
            {
            }

            try
            {
                var documents = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
                if (!string.IsNullOrWhiteSpace(documents)) baseFolders.Add(documents);
            }
            catch
            {
            }

            try
            {
                var downloads = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                    "Downloads");
                if (!string.IsNullOrWhiteSpace(downloads)) baseFolders.Add(downloads);
            }
            catch
            {
            }

            return baseFolders.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        }

        private void InitializeWatchers()
        {
            var baseFolders = GetBaseFolders();
            if (baseFolders.Count == 0)
                return;

            lock (_watcherLock)
            {
                foreach (var folder in baseFolders)
                {
                    if (string.IsNullOrWhiteSpace(folder) || !Directory.Exists(folder))
                        continue;

                    try
                    {
                        var watcher = new FileSystemWatcher(folder)
                        {
                            NotifyFilter = NotifyFilters.FileName | NotifyFilters.DirectoryName | NotifyFilters.LastWrite | NotifyFilters.Size,
                            IncludeSubdirectories = true,
                            EnableRaisingEvents = true,
                            InternalBufferSize = 32768
                        };

                        watcher.Changed += OnCanaryChanged;
                        watcher.Created += OnCanaryChanged;
                        watcher.Deleted += OnCanaryChanged;
                        watcher.Renamed += OnCanaryRenamed;
                        watcher.Error += OnWatcherError;

                        _watchers.Add(watcher);
                    }
                    catch (Exception ex)
                    {
                        Debug.WriteLine($"LHE HiddenCanaryDetector: Failed to create watcher for {folder}: {ex.Message}");
                    }
                }
            }
        }

        private void OnCanaryChanged(object sender, FileSystemEventArgs e)
        {
            try
            {
                if (_disposed || !_isRunning || _cancellationToken.IsCancellationRequested || _suppressEvents)
                    return;

                if (!IsCanaryPath(e.FullPath))
                    return;

                HandleCanaryEvent(e.FullPath, e.ChangeType);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"LHE HiddenCanaryDetector: OnCanaryChanged error: {ex.Message}");
            }
        }

        private void OnCanaryRenamed(object sender, RenamedEventArgs e)
        {
            try
            {
                if (_disposed || !_isRunning || _cancellationToken.IsCancellationRequested || _suppressEvents)
                    return;

                if (!IsCanaryPath(e.OldFullPath) && !IsCanaryPath(e.FullPath))
                    return;

                HandleCanaryEvent(e.FullPath, WatcherChangeTypes.Renamed);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"LHE HiddenCanaryDetector: OnCanaryRenamed error: {ex.Message}");
            }
        }

        private void OnWatcherError(object sender, ErrorEventArgs e)
        {
            try
            {
                Debug.WriteLine($"LHE HiddenCanaryDetector: Watcher error: {e?.GetException()?.Message ?? "Unknown"}");
            }
            catch
            {
            }
        }

        private bool IsCanaryPath(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
                return false;

            lock (_canaryLock)
            {
                return _canaryPaths.Contains(path);
            }
        }

        private void HandleCanaryEvent(string path, WatcherChangeTypes changeType)
        {
            var processName = GetForegroundProcessNameSafe();
            if (!string.IsNullOrWhiteSpace(processName) && SafeProcesses.Contains(processName))
                return;

            if (ShouldSuppressDuplicateAlert(path))
                return;

            var changeDescription = changeType.ToString();
            _dispatcher.Enqueue(
                "Canary File Touched",
                $"A protected canary file/folder was {changeDescription}: {path}\n" +
                $"Foreground process: {(string.IsNullOrWhiteSpace(processName) ? "Unknown" : processName)}");
        }

        private bool ShouldSuppressDuplicateAlert(string path)
        {
            var now = DateTime.UtcNow;
            if (_recentAlerts.TryGetValue(path, out var lastAlert))
            {
                if ((now - lastAlert).TotalSeconds < 10)
                    return true;
            }

            _recentAlerts[path] = now;
            return false;
        }

        private void CleanupAlertCache()
        {
            var cutoff = DateTime.UtcNow.AddSeconds(-30);
            foreach (var entry in _recentAlerts.ToArray())
            {
                if (entry.Value < cutoff)
                    _recentAlerts.TryRemove(entry.Key, out _);
            }
        }

        private void DisposeWatchers()
        {
            lock (_watcherLock)
            {
                foreach (var watcher in _watchers.ToArray())
                {
                    try
                    {
                        watcher.EnableRaisingEvents = false;
                        watcher.Changed -= OnCanaryChanged;
                        watcher.Created -= OnCanaryChanged;
                        watcher.Deleted -= OnCanaryChanged;
                        watcher.Renamed -= OnCanaryRenamed;
                        watcher.Error -= OnWatcherError;
                        watcher.Dispose();
                    }
                    catch
                    {
                    }
                }
                _watchers.Clear();
            }
        }

        private static string GetForegroundProcessNameSafe()
        {
            try
            {
                var hwnd = GetForegroundWindow();
                if (hwnd == IntPtr.Zero)
                    return null;

                if (GetWindowThreadProcessId(hwnd, out var pid) == 0 || pid == 0)
                    return null;

                using (var process = Process.GetProcessById((int)pid))
                {
                    return process.ProcessName;
                }
            }
            catch
            {
                return null;
            }
        }

        [DllImport("user32.dll")]
        private static extern IntPtr GetForegroundWindow();

        [DllImport("user32.dll")]
        private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

        public void Dispose()
        {
            if (_disposed)
                return;

            _disposed = true;
            Cleanup();
        }
    }
}
