using System;
using System.IO;
using System.Windows;
using System.Windows.Media;

namespace VulnGuard_Project
{
    public class AudioManager
    {
        private readonly MediaPlayer _player = new MediaPlayer();
        private bool _muted = false;
        private bool _started = false;

        private const string MusicFile = "ambient_bg.mp3";

        public void StartMusic()
        {
            try
            {
                string musicPath = ExtractResourceToTempFile(MusicFile);
                if (string.IsNullOrWhiteSpace(musicPath) || !File.Exists(musicPath)) return;

                _player.Open(new Uri(musicPath, UriKind.Absolute));
                _player.Volume = 0.4;
                _player.MediaEnded += (s, e) =>
                {
                    _player.Position = TimeSpan.Zero;
                    _player.Play();
                };
                _player.Play();
                _started = true;
            }
            catch { }
        }

        private static string ExtractResourceToTempFile(string resourceName)
        {
            var resourceUri = new Uri($"pack://application:,,,/{resourceName}", UriKind.Absolute);
            var resource = System.Windows.Application.GetResourceStream(resourceUri);
            if (resource?.Stream == null) return "";

            string tempDir = Path.Combine(Path.GetTempPath(), "VulnGuard");
            Directory.CreateDirectory(tempDir);

            string tempPath = Path.Combine(tempDir, resourceName);
            using var output = File.Create(tempPath);
            resource.Stream.CopyTo(output);

            return tempPath;
        }

        public void ToggleMute()
        {
            if (!_started) return;
            _muted = !_muted;
            _player.IsMuted = _muted;
        }

        public bool IsMuted => _muted;
    }
}
